/*
Copyright 2020 The cert-manager Authors.

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
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/cert-manager/cert-manager/pkg/util"
	vault "github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

const vaultToken = "vault-root-token"

// VaultInitializer holds the state of a configured Vault PKI. We use the same
// Vault server for all tests. PKIs are mounted and unmounted for each test
// scenario that uses them.
type VaultInitializer struct {
	kubeClient kubernetes.Interface
	client     *vault.Client

	details Details

	rootMount          string
	intermediateMount  string
	role               string // AppRole auth role
	appRoleAuthPath    string // AppRole auth mount point in Vault
	kubernetesAuthPath string // Kubernetes auth mount point in Vault

	// Whether the intermediate CA should be configured with root CA
	configureWithRoot      bool
	kubernetesAPIServerURL string // Kubernetes API Server URL
}

func NewVaultInitializerAppRole(
	kubeClient kubernetes.Interface,
	details Details,
	configureWithRoot bool,
) *VaultInitializer {
	testId := util.RandStringRunes(10)
	rootMount := fmt.Sprintf("%s-root-ca", testId)
	intermediateMount := fmt.Sprintf("%s-intermediate-ca", testId)
	role := fmt.Sprintf("%s-role", testId)
	appRoleAuthPath := fmt.Sprintf("%s-auth-approle", testId)

	return &VaultInitializer{
		kubeClient: kubeClient,
		details:    details,

		rootMount:         rootMount,
		intermediateMount: intermediateMount,
		role:              role,
		appRoleAuthPath:   appRoleAuthPath,

		configureWithRoot: configureWithRoot,
	}
}

func NewVaultInitializerKubernetes(
	kubeClient kubernetes.Interface,
	details Details,
	configureWithRoot bool,
	apiServerURL string,
) *VaultInitializer {
	testId := util.RandStringRunes(10)
	rootMount := fmt.Sprintf("%s-root-ca", testId)
	intermediateMount := fmt.Sprintf("%s-intermediate-ca", testId)
	role := fmt.Sprintf("%s-role", testId)
	kubernetesAuthPath := fmt.Sprintf("%s-auth-kubernetes", testId)

	return &VaultInitializer{
		kubeClient: kubeClient,
		details:    details,

		rootMount:          rootMount,
		intermediateMount:  intermediateMount,
		role:               role,
		kubernetesAuthPath: kubernetesAuthPath,

		configureWithRoot:      configureWithRoot,
		kubernetesAPIServerURL: apiServerURL,
	}
}

func NewVaultInitializerAllAuth(
	kubeClient kubernetes.Interface,
	details Details,
	configureWithRoot bool,
	apiServerURL string,
) *VaultInitializer {
	testId := util.RandStringRunes(10)
	rootMount := fmt.Sprintf("%s-root-ca", testId)
	intermediateMount := fmt.Sprintf("%s-intermediate-ca", testId)
	role := fmt.Sprintf("%s-role", testId)
	appRoleAuthPath := fmt.Sprintf("%s-auth-approle", testId)
	kubernetesAuthPath := fmt.Sprintf("%s-auth-kubernetes", testId)

	return &VaultInitializer{
		kubeClient: kubeClient,
		details:    details,

		rootMount:          rootMount,
		intermediateMount:  intermediateMount,
		role:               role,
		appRoleAuthPath:    appRoleAuthPath,
		kubernetesAuthPath: kubernetesAuthPath,

		configureWithRoot:      configureWithRoot,
		kubernetesAPIServerURL: apiServerURL,
	}
}

func (v *VaultInitializer) RootMount() string {
	return v.rootMount
}

func (v *VaultInitializer) IntermediateMount() string {
	return v.intermediateMount
}

func (v *VaultInitializer) Role() string {
	return v.role
}

// AppRoleAuthPath returns the AppRole auth mount point in Vault.
// The format is "xxxxx-auth-approle".
func (v *VaultInitializer) AppRoleAuthPath() string {
	return v.appRoleAuthPath
}

// KubernetesAuthPath returns the Kubernetes auth mount point in Vault.
// The format is "/v1/auth/xxxxx-auth-kubernetes".
func (v *VaultInitializer) KubernetesAuthPath() string {
	return path.Join("/v1", "auth", v.kubernetesAuthPath)
}

func NewVaultAppRoleSecret(secretName, secretId string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: secretName,
		},
		StringData: map[string]string{
			"secretkey": secretId,
		},
	}
}

func NewVaultKubernetesSecret(secretName, serviceAccountName string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": serviceAccountName,
			},
		},
		Type: "kubernetes.io/service-account-token",
	}
}

// Set up a new Vault client, port-forward to the Vault instance.
func (v *VaultInitializer) Init() error {
	cfg := vault.DefaultConfig()
	cfg.Address = v.details.ProxyURL

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(v.details.VaultCA); !ok {
		return fmt.Errorf("error loading Vault CA bundle: %s", v.details.VaultCA)
	}
	cfg.HttpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = caCertPool

	client, err := vault.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("unable to initialize vault client: %s", err)
	}

	client.SetToken(vaultToken)
	v.client = client

	// Wait for port-forward to be ready
	{
		proxyUrl, err := url.Parse(v.details.ProxyURL)
		if err != nil {
			return fmt.Errorf("error parsing proxy URL: %s", err.Error())
		}
		var lastError error
		err = wait.PollUntilContextTimeout(context.TODO(), time.Second, 20*time.Second, true, func(ctx context.Context) (bool, error) {
			conn, err := net.DialTimeout("tcp", proxyUrl.Host, time.Second)
			if err != nil {
				lastError = err
				return false, nil
			}

			conn.Close()
			return true, nil
		})
		if err != nil {
			return fmt.Errorf("error waiting for port-forward to be ready: %w", lastError)
		}
	}

	// Wait for Vault to be ready
	{
		var lastError error
		err = wait.PollUntilContextTimeout(context.TODO(), time.Second, 20*time.Second, true, func(ctx context.Context) (bool, error) {
			_, err := v.client.Sys().Health()
			if err != nil {
				lastError = err
				return false, nil
			}

			return true, nil
		})
		if err != nil {
			return fmt.Errorf("error waiting for Vault to be ready: %w", lastError)
		}
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

// Set up a Vault PKI.
func (v *VaultInitializer) Setup() error {
	// Enable a new Vault secrets engine at v.RootMount
	if err := v.mountPKI(v.rootMount, "87600h"); err != nil {
		return err
	}

	// Generate a self-signed CA cert using the engine at v.RootMount
	rootCa, err := v.generateRootCert()
	if err != nil {
		return err
	}

	// Configure issuing certificate endpoints and CRL distribution points to be
	// set on certs issued by v.RootMount.
	if err := v.configureCert(v.rootMount); err != nil {
		return err

	}

	// Enable a new Vault secrets engine at v.intermediateMount
	if err := v.mountPKI(v.intermediateMount, "43800h"); err != nil {
		return err
	}

	// Generate a CSR for secrets engine at v.intermediateMount
	csr, err := v.generateIntermediateSigningReq()
	if err != nil {
		return err
	}

	// Issue a new intermediate CA from v.RootMount for the CSR created above.
	intermediateCa, err := v.signCertificate(csr)
	if err != nil {
		return err
	}

	// Set the engine at v.intermediateMount as an intermediateCA using the cert
	// issued by v.RootMount, above and optionally the root CA cert.
	caChain := intermediateCa
	if v.configureWithRoot {
		caChain = fmt.Sprintf("%s\n%s", intermediateCa, rootCa)
	}
	if err := v.importSignIntermediate(caChain, v.intermediateMount); err != nil {
		return err
	}

	// Configure issuing certificate endpoints and CRL distribution points to be
	// set on certs issued by v.intermediateMount.
	if err := v.configureCert(v.intermediateMount); err != nil {
		return err
	}

	if err := v.configureIntermediateRoles(); err != nil {
		return err
	}

	if v.appRoleAuthPath != "" {
		if err := v.setupAppRoleAuth(); err != nil {
			return err
		}
	}

	if v.kubernetesAuthPath != "" {
		if err := v.setupKubernetesBasedAuth(); err != nil {
			return err
		}
	}

	return nil
}

func (v *VaultInitializer) Clean() error {
	if err := v.client.Sys().Unmount("/" + v.intermediateMount); err != nil {
		return fmt.Errorf("unable to unmount %v: %v", v.intermediateMount, err)
	}
	if err := v.client.Sys().Unmount("/" + v.rootMount); err != nil {
		return fmt.Errorf("unable to unmount %v: %v", v.rootMount, err)
	}

	return nil
}

func (v *VaultInitializer) CreateAppRole() (string, string, error) {
	// create policy
	policy := fmt.Sprintf(`path "%s" { capabilities = [ "create", "update" ] }`, v.IntermediateSignPath())
	err := v.client.Sys().PutPolicy(v.role, policy)
	if err != nil {
		return "", "", fmt.Errorf("error creating policy: %s", err.Error())
	}

	// # create approle
	params := map[string]string{
		"period":   "24h",
		"policies": v.role,
	}

	baseUrl := path.Join("/v1", "auth", v.appRoleAuthPath, "role", v.role)
	_, err = v.callVault("POST", baseUrl, "", params)
	if err != nil {
		return "", "", fmt.Errorf("error creating approle: %s", err.Error())
	}

	// # read the role-id
	url := path.Join(baseUrl, "role-id")
	roleId, err := v.callVault("GET", url, "role_id", map[string]string{})
	if err != nil {
		return "", "", fmt.Errorf("error reading role_id: %s", err.Error())
	}

	// # read the secret-id
	url = path.Join(baseUrl, "secret-id")
	secretId, err := v.callVault("POST", url, "secret_id", map[string]string{})
	if err != nil {
		return "", "", fmt.Errorf("error reading secret_id: %s", err.Error())
	}

	return roleId, secretId, nil
}

func (v *VaultInitializer) CleanAppRole() error {
	url := path.Join("/v1", "auth", v.appRoleAuthPath, "role", v.role)
	_, err := v.callVault("DELETE", url, "", nil)
	if err != nil {
		return fmt.Errorf("error deleting AppRole: %s", err.Error())
	}

	err = v.client.Sys().DeletePolicy(v.role)
	if err != nil {
		return fmt.Errorf("error deleting policy: %s", err.Error())
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
		return fmt.Errorf("error mounting %s: %s", mount, err.Error())
	}

	return nil
}

func (v *VaultInitializer) generateRootCert() (string, error) {
	params := map[string]string{
		"common_name":          "Root CA",
		"ttl":                  "87600h",
		"exclude_cn_from_sans": "true",
		"key_type":             "ec",
		"key_bits":             "256",
	}
	url := path.Join("/v1", v.rootMount, "root", "generate", "internal")

	cert, err := v.callVault("POST", url, "certificate", params)
	if err != nil {
		return "", fmt.Errorf("error generating CA root certificate: %s", err.Error())
	}

	return cert, nil
}

func (v *VaultInitializer) generateIntermediateSigningReq() (string, error) {
	params := map[string]string{
		"common_name":          "Intermediate CA",
		"ttl":                  "43800h",
		"exclude_cn_from_sans": "true",
		"key_type":             "ec",
		"key_bits":             "256",
	}
	url := path.Join("/v1", v.intermediateMount, "intermediate", "generate", "internal")

	csr, err := v.callVault("POST", url, "csr", params)
	if err != nil {
		return "", fmt.Errorf("error generating CA intermediate certificate: %s", err.Error())
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
	url := path.Join("/v1", v.rootMount, "root", "sign-intermediate")

	cert, err := v.callVault("POST", url, "certificate", params)
	if err != nil {
		return "", fmt.Errorf("error signing intermediate Vault certificate: %s", err.Error())
	}

	return cert, nil
}

func (v *VaultInitializer) importSignIntermediate(caChain, intermediateMount string) error {
	params := map[string]string{
		"certificate": caChain,
	}
	url := path.Join("/v1", intermediateMount, "intermediate", "set-signed")

	_, err := v.callVault("POST", url, "", params)
	if err != nil {
		return fmt.Errorf("error importing intermediate Vault certificate: %s", err.Error())
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
		return fmt.Errorf("error configuring Vault certificate: %s", err.Error())
	}

	return nil
}

func (v *VaultInitializer) configureIntermediateRoles() error {
	params := map[string]string{
		"allow_any_name":     "true",
		"max_ttl":            "2160h",
		"key_type":           "any",
		"require_cn":         "false",
		"allowed_uri_sans":   "spiffe://cluster.local/*",
		"enforce_hostnames":  "false",
		"allow_bare_domains": "true",
	}
	url := path.Join("/v1", v.intermediateMount, "roles", v.role)

	_, err := v.callVault("POST", url, "", params)
	if err != nil {
		return fmt.Errorf("error creating role %s: %s", v.role, err.Error())
	}

	return nil
}

func (v *VaultInitializer) setupAppRoleAuth() error {
	// vault auth-enable approle
	auths, err := v.client.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("error fetching auth mounts: %s", err.Error())
	}

	if _, ok := auths[v.appRoleAuthPath]; ok {
		return nil
	}

	options := &vault.EnableAuthOptions{
		Type: "approle",
	}
	if err := v.client.Sys().EnableAuthWithOptions(v.appRoleAuthPath, options); err != nil {
		return fmt.Errorf("error enabling approle: %s", err.Error())
	}

	return nil
}

func (v *VaultInitializer) setupKubernetesBasedAuth() error {
	// vault auth-enable kubernetes
	auths, err := v.client.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("error fetching auth mounts: %s", err.Error())
	}

	if _, ok := auths[v.kubernetesAuthPath]; ok {
		return nil
	}

	options := &vault.EnableAuthOptions{
		Type: "kubernetes",
	}
	if err := v.client.Sys().EnableAuthWithOptions(v.kubernetesAuthPath, options); err != nil {
		return fmt.Errorf("error enabling approle: %s", err.Error())
	}

	// vault write auth/kubernetes/config
	params := map[string]string{
		"kubernetes_host": v.kubernetesAPIServerURL,
		// Since Vault 1.9, HashiCorp recommends disabling the iss validation.
		// If we don't disable the iss validation, we can't use the same
		// Kubernetes auth config for both testing the "secretRef" Kubernetes
		// auth and the "serviceAccountRef" Kubernetes auth because the former
		// relies on static tokens for which "iss" is
		// "kubernetes/serviceaccount", and the later relies on bound tokens for
		// which "iss" is "https://kubernetes.default.svc.cluster.local".
		// https://www.vaultproject.io/docs/auth/kubernetes#kubernetes-1-21
		"disable_iss_validation": "true",
	}

	url := path.Join("/v1", "auth", v.kubernetesAuthPath, "config")
	if _, err = v.callVault("POST", url, "", params); err != nil {
		return fmt.Errorf("error configuring kubernetes auth backend: %s", err.Error())
	}

	return nil
}

// CreateKubernetesrole creates a service account and ClusterRoleBinding for
// Kubernetes auth delegation. The name "boundSA" refers to the Vault param
// "bound_service_account_names".
func (v *VaultInitializer) CreateKubernetesRole(client kubernetes.Interface, boundNS, boundSA string) error {
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: boundSA,
		},
	}
	_, err := client.CoreV1().ServiceAccounts(boundNS).Create(context.TODO(), serviceAccount, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating ServiceAccount for Kubernetes auth: %s", err.Error())
	}

	// create policy
	policy := fmt.Sprintf(`path "%s" { capabilities = [ "create", "update" ] }`, v.IntermediateSignPath())
	err = v.client.Sys().PutPolicy(v.role, policy)
	if err != nil {
		return fmt.Errorf("error creating policy: %s", err.Error())
	}

	// # create approle
	params := map[string]string{
		"period":                           "24h",
		"policies":                         v.role,
		"bound_service_account_names":      boundSA,
		"bound_service_account_namespaces": boundNS,
	}

	baseUrl := path.Join("/v1", "auth", v.kubernetesAuthPath, "role", v.role)
	_, err = v.callVault("POST", baseUrl, "", params)
	if err != nil {
		return fmt.Errorf("error creating kubernetes role: %s", err.Error())
	}

	return nil
}

func (v *VaultInitializer) IntermediateSignPath() string {
	return path.Join(v.intermediateMount, "sign", v.role)
}

// CleanKubernetesRole cleans up the ClusterRoleBinding and ServiceAccount for Kubernetes auth delegation
func (v *VaultInitializer) CleanKubernetesRole(client kubernetes.Interface, boundNS, boundSA string) error {
	if err := client.CoreV1().ServiceAccounts(boundNS).Delete(context.TODO(), boundSA, metav1.DeleteOptions{}); err != nil {
		return err
	}

	// vault delete auth/kubernetes/role/<roleName>
	url := path.Join("/v1", "auth", v.kubernetesAuthPath, "role", v.role)
	_, err := v.callVault("DELETE", url, "", nil)
	if err != nil {
		return fmt.Errorf("error cleaning up kubernetes auth role: %s", err.Error())
	}

	err = v.client.Sys().DeletePolicy(v.role)
	if err != nil {
		return fmt.Errorf("error deleting policy: %s", err.Error())
	}

	return nil
}

func RoleAndBindingForServiceAccountRefAuth(roleName, namespace, serviceAccount string) (*rbacv1.Role, *rbacv1.RoleBinding) {
	return &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      roleName,
				Namespace: namespace,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"serviceaccounts/token"},
					ResourceNames: []string{serviceAccount},
					Verbs:         []string{"create"},
				},
			},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: roleName,
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     roleName,
			},
			Subjects: []rbacv1.Subject{
				{
					Name:      "cert-manager",
					Namespace: "cert-manager",
					Kind:      "ServiceAccount",
				},
			},
		}
}

// CreateKubernetesRoleForServiceAccountRefAuth creates a service account and a
// role for using the "serviceAccountRef" field.
func CreateKubernetesRoleForServiceAccountRefAuth(client kubernetes.Interface, roleName, saNS, saName string) error {
	role, binding := RoleAndBindingForServiceAccountRefAuth(roleName, saNS, saName)
	_, err := client.RbacV1().Roles(saNS).Create(context.TODO(), role, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating Role for Kubernetes auth ServiceAccount with serviceAccountRef: %s", err.Error())
	}
	_, err = client.RbacV1().RoleBindings(saNS).Create(context.TODO(), binding, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating RoleBinding for Kubernetes auth ServiceAccount with serviceAccountRef: %s", err.Error())
	}

	return nil
}

func CleanKubernetesRoleForServiceAccountRefAuth(client kubernetes.Interface, roleName, saNS, saName string) error {
	if err := client.RbacV1().RoleBindings(saNS).Delete(context.TODO(), roleName, metav1.DeleteOptions{}); err != nil {
		return err
	}

	if err := client.RbacV1().Roles(saNS).Delete(context.TODO(), roleName, metav1.DeleteOptions{}); err != nil {
		return err
	}

	if err := client.CoreV1().ServiceAccounts(saNS).Delete(context.TODO(), saName, metav1.DeleteOptions{}); err != nil {
		return err
	}

	return nil
}
