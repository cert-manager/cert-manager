/*
Copyright 2019 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vault

import (
	"crypto/x509"
	"fmt"
	"math/rand"
	"net/http"
	"os/exec"
	"path"
	"time"

	"k8s.io/client-go/kubernetes"

	vault "github.com/hashicorp/vault/api"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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

func NewVaultServiceAccount(name string) *v1.ServiceAccount {
	return &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
}

func NewVaultServiceAccountRole(namespace string) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("auth-delegator:%s:vault", namespace),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
		},
	}
}

func NewVaultServiceAccountClusterRoleBinding(roleName, namespace, subject string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: roleName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     roleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Name:      subject,
				Kind:      "ServiceAccount",
				Namespace: namespace,
			},
		},
	}
}

func NewVaultKubernetesSecret(name string, serviceAccountName string) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": serviceAccountName,
			},
		},
		Type: "kubernetes.io/service-account-token",
	}
}

type VaultInitializer struct {
	proxyCmd *exec.Cmd
	client   *vault.Client

	Details

	RootMount          string
	IntermediateMount  string
	Role               string // AppRole auth Role
	AppRoleAuthPath    string // AppRole auth mount point in Vault
	KubernetesAuthPath string // Kubernetes auth mount point in Vault
	APIServerURL       string // Kubernetes API Server URL
	APIServerCA        string // Kubernetes API Server CA certificate
}

func (v *VaultInitializer) Init() error {
	rand.Seed(time.Now().UnixNano())
	listenPort := 30000 + rand.Intn(5000)

	// TODO: we need to make this port-forward more robust.
	// Currently, it's possible that the connection gets dropped causing later
	// init commands to fail.
	args := []string{"port-forward", "-n", v.Details.Namespace, v.Details.PodName, fmt.Sprintf("%d:8200", listenPort)}
	cmd := exec.Command(v.Details.Kubectl, args...)
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("Error starting port-forward: %s", err.Error())
	}

	if v.AppRoleAuthPath == "" {
		v.AppRoleAuthPath = "approle"
	}

	if v.KubernetesAuthPath == "" {
		v.KubernetesAuthPath = "kubernetes"
	}

	// Wait for 7s to allow port-forward to actually start.
	// We wait longer than expected, as in highly parallel e2e runs this may
	// take some time to start.
	time.Sleep(7 * time.Second)

	// Cross our fingers and hope that it's started :this_is_fine:

	cfg := vault.DefaultConfig()
	cfg.Address = fmt.Sprintf("https://127.0.0.1:%d", listenPort)

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(v.VaultCA)
	if ok == false {
		return fmt.Errorf("error loading Vault CA bundle")
	}

	cfg.HttpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = caCertPool

	client, err := vault.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("Unable to initialize vault client: %s", err.Error())
	}

	client.SetToken(vaultToken)
	v.client = client
	return nil
}

func (v *VaultInitializer) Setup() error {
	if err := v.mountPKI(v.RootMount, "87600h"); err != nil {
		return err
	}

	rootCa, err := v.generateRootCert()
	if err != nil {
		return err
	}

	if err := v.configureCert(v.RootMount); err != nil {
		return err

	}

	if err := v.mountPKI(v.IntermediateMount, "43800h"); err != nil {
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

	if err := v.importSignIntermediate(intermediateCa, rootCa, v.IntermediateMount); err != nil {
		return err
	}

	if err := v.configureCert(v.IntermediateMount); err != nil {
		return err
	}

	if err := v.setupRole(); err != nil {
		return err
	}

	if err := v.setupKubernetesBasedAuth(); err != nil {
		return err
	}

	return nil
}

func (v *VaultInitializer) Clean() error {
	if err := v.client.Sys().Unmount("/" + v.IntermediateMount); err != nil {
		return fmt.Errorf("Unable to unmount %v: %v", v.IntermediateMount, err)
	}
	if err := v.client.Sys().Unmount("/" + v.RootMount); err != nil {
		return fmt.Errorf("Unable to unmount %v: %v", v.RootMount, err)
	}

	v.proxyCmd.Process.Kill()
	v.proxyCmd.Process.Wait()

	return nil
}

func (v *VaultInitializer) CreateAppRole() (string, string, error) {
	// create policy
	role_path := path.Join(v.IntermediateMount, "sign", v.Role)
	policy := fmt.Sprintf("path \"%s\" { capabilities = [ \"create\", \"update\" ] }", role_path)
	err := v.client.Sys().PutPolicy(v.Role, policy)
	if err != nil {
		return "", "", fmt.Errorf("Error creating policy: %s", err.Error())
	}

	// # create approle
	params := map[string]string{
		"period":   "24h",
		"policies": v.Role,
	}

	baseUrl := path.Join("/v1", "auth", v.AppRoleAuthPath, "role", v.Role)
	_, err = v.callVault("POST", baseUrl, "", params)
	if err != nil {
		return "", "", fmt.Errorf("Error creating approle: %s", err.Error())
	}

	// # read the role-id
	url := path.Join(baseUrl, "role-id")
	roleId, err := v.callVault("GET", url, "role_id", map[string]string{})
	if err != nil {
		return "", "", fmt.Errorf("Error reading role_id: %s", err.Error())
	}

	// # read the secret-id
	url = path.Join(baseUrl, "secret-id")
	secretId, err := v.callVault("POST", url, "secret_id", map[string]string{})
	if err != nil {
		return "", "", fmt.Errorf("Error reading secret_id: %s", err.Error())
	}

	return roleId, secretId, nil
}

func (v *VaultInitializer) CleanAppRole() error {
	url := path.Join("/v1", "auth", v.AppRoleAuthPath, "role", v.Role)
	_, err := v.callVault("DELETE", url, "", map[string]string{})
	if err != nil {
		return fmt.Errorf("Error deleting AppRole: %s", err.Error())
	}

	err = v.client.Sys().DeletePolicy(v.Role)
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
		"common_name":          "Root CA",
		"ttl":                  "87600h",
		"exclude_cn_from_sans": "true",
	}
	url := path.Join("/v1", v.RootMount, "root", "generate", "internal")

	cert, err := v.callVault("POST", url, "certificate", params)
	if err != nil {
		return "", fmt.Errorf("Error generating CA root certificate: %s", err.Error())
	}

	return cert, nil
}

func (v *VaultInitializer) generateIntermediateSigningReq() (string, error) {
	params := map[string]string{
		"common_name":          "Intermediate CA",
		"ttl":                  "43800h",
		"exclude_cn_from_sans": "true",
	}
	url := path.Join("/v1", v.IntermediateMount, "intermediate", "generate", "internal")

	csr, err := v.callVault("POST", url, "csr", params)
	if err != nil {
		return "", fmt.Errorf("Error generating CA intermediate certificate: %s", err.Error())
	}

	return csr, nil
}

func (v *VaultInitializer) signCertificate(csr string) (string, error) {
	params := map[string]string{
		"use_csr_values":       "true",
		"ttl":                  "43800h",
		"exclude_cn_from_sans": "true",
		"csr":                  csr,
	}
	url := path.Join("/v1", v.RootMount, "root", "sign-intermediate")

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
		"issuing_certificates":    fmt.Sprintf("https://vault.vault:8200/v1/%s/ca", mount),
		"crl_distribution_points": fmt.Sprintf("https://vault.vault:8200/v1/%s/crl", mount),
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

	if _, ok := auths[v.AppRoleAuthPath]; !ok {
		options := &vault.EnableAuthOptions{Type: "approle"}
		if err := v.client.Sys().EnableAuthWithOptions(v.AppRoleAuthPath, options); err != nil {
			return fmt.Errorf("Error enabling approle: %s", err.Error())
		}
	}

	params := map[string]string{
		"allow_any_name":   "true",
		"max_ttl":          "2160h",
		"key_type":         "any",
		"require_cn":       "false",
		"allowed_uri_sans": "spiffe://cluster.local/*",
	}
	url := path.Join("/v1", v.IntermediateMount, "roles", v.Role)

	_, err = v.callVault("POST", url, "", params)
	if err != nil {
		return fmt.Errorf("Error creating role %s: %s", v.Role, err.Error())
	}

	return nil
}

func (v *VaultInitializer) setupKubernetesBasedAuth() error {
	if len(v.APIServerURL) == 0 {
		// skip initialization if not provided
		return nil
	}

	// vault auth-enable kubernetes
	auths, err := v.client.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("Error fetching auth mounts: %s", err.Error())
	}

	if _, ok := auths[v.KubernetesAuthPath]; !ok {
		options := &vault.EnableAuthOptions{Type: "kubernetes"}
		if err := v.client.Sys().EnableAuthWithOptions(v.KubernetesAuthPath, options); err != nil {
			return fmt.Errorf("Error enabling kubernetes auth: %s", err.Error())
		}
	}

	// vault write auth/kubernetes/config
	params := map[string]string{
		"kubernetes_host":    v.APIServerURL,
		"kubernetes_ca_cert": v.APIServerCA,
	}

	url := fmt.Sprintf("/v1/auth/%s/config", v.KubernetesAuthPath)
	_, err = v.callVault("POST", url, "", params)

	if err != nil {
		return fmt.Errorf("error configuring kubernetes auth backend: %s", err.Error())
	}

	return nil
}

// CreateKubernetesRole creates a service account and ClusterRoleBinding for Kubernetes auth delegation
func (v *VaultInitializer) CreateKubernetesRole(client kubernetes.Interface, namespace, roleName, serviceAccountName string) error {
	serviceAccount := NewVaultServiceAccount(serviceAccountName)
	_, err := client.CoreV1().ServiceAccounts(namespace).Create(serviceAccount)

	if err != nil {
		return fmt.Errorf("error creating ServiceAccount for Kubernetes auth: %s", err.Error())
	}

	role := NewVaultServiceAccountRole(namespace)
	_, err = client.RbacV1().ClusterRoles().Create(role)
	if err != nil {
		return fmt.Errorf("error creating Role for Kubernetes auth ServiceAccount: %s", err.Error())
	}

	roleBinding := NewVaultServiceAccountClusterRoleBinding(role.Name, namespace, serviceAccountName)
	_, err = client.RbacV1().ClusterRoleBindings().Create(roleBinding)

	if err != nil {
		return fmt.Errorf("error creating RoleBinding for Kubernetes auth ServiceAccount: %s", err.Error())
	}

	// vault write auth/kubernetes/role/<roleName>
	roleParams := map[string]string{
		"bound_service_account_names":      serviceAccountName,
		"bound_service_account_namespaces": namespace,
		"policies":                         "[" + v.Role + "]",
	}

	url := path.Join(fmt.Sprintf("/v1/auth/%s/role", v.KubernetesAuthPath), roleName)
	_, err = v.callVault("POST", url, "", roleParams)
	if err != nil {
		return fmt.Errorf("error configuring kubernetes auth role: %s", err.Error())
	}

	return nil
}

// CleanKubernetesRole cleans up the ClusterRoleBinding and ServiceAccount for Kubernetes auth delegation
func (v *VaultInitializer) CleanKubernetesRole(client kubernetes.Interface, namespace, roleName, serviceAccountName string) error {
	if err := client.RbacV1().RoleBindings(namespace).Delete(roleName, nil); err != nil {
		return err
	}

	if err := client.RbacV1().Roles(namespace).Delete(roleName, nil); err != nil {
		return err
	}

	if err := client.CoreV1().ServiceAccounts(namespace).Delete(serviceAccountName, nil); err != nil {
		return err
	}

	// vault delete auth/kubernetes/role/<roleName>
	url := path.Join(fmt.Sprintf("/v1/auth/%s/role", v.KubernetesAuthPath), roleName)
	_, err := v.callVault("DELETE", url, "", nil)
	if err != nil {
		return fmt.Errorf("error cleaning up kubernetes auth role: %s", err.Error())
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
