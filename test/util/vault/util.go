package vault

import (
	"fmt"
	"os/exec"
	"path"
	"time"

	"github.com/golang/glog"
	vault "github.com/hashicorp/vault/api"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const vaultToken = "vault-root-token"

func NewVaultTokenSecret(name string) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		StringData: map[string]string{
			"token": vaultToken,
		},
	}
}

func NewVaultAppRoleSecret(name, secretId string) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		StringData: map[string]string{
			"secretkey": secretId,
		},
	}
}

type VaultInitializer struct {
	proxyCmd          *exec.Cmd
	client            *vault.Client
	rootMount         string
	intermediateMount string
	role              string
}

func NewVaultInitializer(container, rootMount, intermediateMount, role string) (*VaultInitializer, error) {
	args := []string{"port-forward", "-n", "vault", container, "8200:8200"}
	cmd := exec.Command("kubectl", args...)
	err := cmd.Start()
	if err != nil {
		glog.Fatalf("Error starting port-forward: %s", err.Error())
	}

	time.Sleep(3 * time.Second)

	cfg := vault.DefaultConfig()
	cfg.Address = "http://127.0.0.1:8200"
	client, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("Unable to initialize vault client: %s", err.Error())
	}

	client.SetToken(vaultToken)

	return &VaultInitializer{
		proxyCmd:          cmd,
		client:            client,
		rootMount:         rootMount,
		intermediateMount: intermediateMount,
		role:              role,
	}, nil
}

func (v *VaultInitializer) Setup() error {
	if err := v.mountPKI(v.rootMount, "87600h"); err != nil {
		return err
	}

	rootCa, err := v.generateRootCert()
	if err != nil {
		return err
	}

	if err := v.configureCert(v.rootMount); err != nil {
		return err

	}

	if err := v.mountPKI(v.intermediateMount, "43800h"); err != nil {
		return err
	}

	csr, err := v.generateIntermediateSigningReq()
	if err != nil {
		return err
	}

	intermediateCa, err := v.signCertificate(csr)
	if err != nil {
		return err
	}

	if err := v.importSignIntermediate(intermediateCa, rootCa, v.intermediateMount); err != nil {
		return err
	}

	if err := v.configureCert(v.intermediateMount); err != nil {
		return err
	}

	if err := v.setupRole(); err != nil {
		return err
	}

	return nil
}

func (v *VaultInitializer) Clean() error {
	if err := v.client.Sys().Unmount("/" + v.intermediateMount); err != nil {
		return fmt.Errorf("Unable to unmount %v: %v", v.intermediateMount, err)
	}
	if err := v.client.Sys().Unmount("/" + v.rootMount); err != nil {
		return fmt.Errorf("Unable to unmount %v: %v", v.rootMount, err)
	}

	v.proxyCmd.Process.Kill()
	v.proxyCmd.Process.Wait()

	return nil
}

func (v *VaultInitializer) CreateAppRole() (string, string, error) {
	// create policy
	role_path := path.Join(v.intermediateMount, "sign", v.role)
	policy := fmt.Sprintf("path \"%s\" { capabilities = [ \"create\", \"update\" ] }", role_path)
	err := v.client.Sys().PutPolicy(v.role, policy)
	if err != nil {
		return "", "", fmt.Errorf("Error creating policy: %s", err.Error())
	}

	// # create approle
	params := map[string]string{
		"period":   "24h",
		"policies": v.role,
	}
	url := path.Join("/v1/auth/approle/role", v.role)
	_, err = v.callVault("POST", url, "", params)
	if err != nil {
		return "", "", fmt.Errorf("Error creating approle: %s", err.Error())
	}

	// # read the role-id
	url = path.Join("/v1/auth/approle/role", v.role, "role-id")
	roleId, err := v.callVault("GET", url, "role_id", map[string]string{})
	if err != nil {
		return "", "", fmt.Errorf("Error reading role_id: %s", err.Error())
	}

	// # read the secret-id
	url = path.Join("/v1/auth/approle/role", v.role, "secret-id")
	secretId, err := v.callVault("POST", url, "secret_id", map[string]string{})
	if err != nil {
		return "", "", fmt.Errorf("Error reading secret_id: %s", err.Error())
	}

	return roleId, secretId, nil
}

func (v *VaultInitializer) CleanAppRole() error {
	url := path.Join("/v1/auth/approle/role", v.role)
	_, err := v.callVault("DELETE", url, "", map[string]string{})
	if err != nil {
		return fmt.Errorf("Error deleting AppRole: %s", err.Error())
	}

	err = v.client.Sys().DeletePolicy(v.role)
	if err != nil {
		return fmt.Errorf("Error deleting policy: %s", err.Error())
	}

	return nil
}

func (v *VaultInitializer) mountPKI(mount, ttl string) error {
	opts := &vault.MountInput{
		Type: "pki",
		Config: vault.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	}
	if err := v.client.Sys().Mount("/"+mount, opts); err != nil {
		return fmt.Errorf("Error mounting %s: %s", mount, err.Error())
	}

	return nil
}

func (v *VaultInitializer) generateRootCert() (string, error) {
	params := map[string]string{
		"common_name": "Root CA",
		"ttl":         "87600h",
		"exclude_cn_from_sans": "true",
	}
	url := path.Join("/v1", v.rootMount, "root", "generate", "internal")

	cert, err := v.callVault("POST", url, "certificate", params)
	if err != nil {
		return "", fmt.Errorf("Error generating CA root certificate: %s", err.Error())
	}

	return cert, nil
}

func (v *VaultInitializer) generateIntermediateSigningReq() (string, error) {
	params := map[string]string{
		"common_name": "Intermediate CA",
		"ttl":         "43800h",
		"exclude_cn_from_sans": "true",
	}
	url := path.Join("/v1", v.intermediateMount, "intermediate", "generate", "internal")

	csr, err := v.callVault("POST", url, "csr", params)
	if err != nil {
		return "", fmt.Errorf("Error generating CA intermediate certificate: %s", err.Error())
	}

	return csr, nil
}

func (v *VaultInitializer) signCertificate(csr string) (string, error) {
	params := map[string]string{
		"use_csr_values": "true",
		"ttl":            "43800h",
		"exclude_cn_from_sans": "true",
		"csr": csr,
	}
	url := path.Join("/v1", v.rootMount, "root", "sign-intermediate")

	cert, err := v.callVault("POST", url, "certificate", params)
	if err != nil {
		return "", fmt.Errorf("Error signing intermediate Vault certificate: %s", err.Error())
	}

	return cert, nil
}

func (v *VaultInitializer) importSignIntermediate(intermediateCa, rootCa, intermediateMount string) error {
	params := map[string]string{
		"certificate": intermediateCa,
	}
	url := path.Join("/v1", intermediateMount, "intermediate", "set-signed")

	_, err := v.callVault("POST", url, "", params)
	if err != nil {
		return fmt.Errorf("Error importing intermediate Vault certificate: %s", err.Error())
	}

	return nil
}

func (v *VaultInitializer) configureCert(mount string) error {
	params := map[string]string{
		"issuing_certificates":    fmt.Sprintf("http://vault.vault:8200/v1/%s/ca", mount),
		"crl_distribution_points": fmt.Sprintf("http://vault.vault:8200/v1/%s/crl", mount),
	}
	url := path.Join("/v1", mount, "config", "urls")

	_, err := v.callVault("POST", url, "", params)
	if err != nil {
		return fmt.Errorf("Error configuring Vault certificate: %s", err.Error())
	}

	return nil
}

func (v *VaultInitializer) setupRole() error {
	// vault auth-enable approle
	auths, err := v.client.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("Error fetching auth mounts: %s", err.Error())
	}
	if _, ok := auths["approle/"]; !ok {
		options := &vault.EnableAuthOptions{Type: "approle"}
		if err := v.client.Sys().EnableAuthWithOptions("approle", options); err != nil {
			return fmt.Errorf("Error enabling approle: %s", err.Error())
		}
	}

	// vault write intermediate-ca/roles/kubernetes-vault allow_any_name=true max_ttl="2160h"
	params := map[string]string{
		"allow_any_name": "true",
		"max_ttl":        "2160h",
	}
	url := path.Join("/v1", v.intermediateMount, "roles", v.role)

	_, err = v.callVault("POST", url, "", params)
	if err != nil {
		return fmt.Errorf("Error creating role %s: %s", v.role, err.Error())
	}

	return nil
}

func (v *VaultInitializer) callVault(method, url, field string, params map[string]string) (string, error) {
	req := v.client.NewRequest(method, url)

	err := req.SetJSONBody(params)
	if err != nil {
		return "", fmt.Errorf("error encoding Vault parameters: %s", err.Error())

	}

	resp, err := v.client.RawRequest(req)
	if err != nil {
		return "", fmt.Errorf("error calling Vault server: %s", err.Error())

	}

	defer resp.Body.Close()

	result := map[string]interface{}{}
	resp.DecodeJSON(&result)

	fieldData := ""
	if field != "" {
		data := result["data"].(map[string]interface{})
		fieldData = data[field].(string)
	}

	return fieldData, err
}
