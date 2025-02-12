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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8srand "k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"github.com/cert-manager/cert-manager/pkg/cmrand"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
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
	clientCertAuthPath string // Client certificate auth mount point in Vault
	kubernetesAuthPath string // Kubernetes auth mount point in Vault

	// Whether the intermediate CA should be configured with root CA
	configureWithRoot      bool
	kubernetesAPIServerURL string // Kubernetes API Server URL
}

func NewVaultInitializerClientCertificate(
	kubeClient kubernetes.Interface,
	details Details,
	configureWithRoot bool,
) *VaultInitializer {
	testId := k8srand.String(10)
	rootMount := fmt.Sprintf("%s-root-ca", testId)
	intermediateMount := fmt.Sprintf("%s-intermediate-ca", testId)
	role := fmt.Sprintf("%s-role", testId)
	clientCertAuthPath := fmt.Sprintf("%s-auth-clientcert", testId)

	return &VaultInitializer{
		kubeClient: kubeClient,
		details:    details,

		rootMount:          rootMount,
		intermediateMount:  intermediateMount,
		role:               role,
		clientCertAuthPath: clientCertAuthPath,

		configureWithRoot: configureWithRoot,
	}
}

func NewVaultInitializerAppRole(
	kubeClient kubernetes.Interface,
	details Details,
	configureWithRoot bool,
) *VaultInitializer {
	testId := k8srand.String(10)
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
	testId := k8srand.String(10)
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
	testId := k8srand.String(10)
	rootMount := fmt.Sprintf("%s-root-ca", testId)
	intermediateMount := fmt.Sprintf("%s-intermediate-ca", testId)
	role := fmt.Sprintf("%s-role", testId)
	appRoleAuthPath := fmt.Sprintf("%s-auth-approle", testId)
	kubernetesAuthPath := fmt.Sprintf("%s-auth-kubernetes", testId)
	clientCertAuthPath := fmt.Sprintf("%s-client-certificate", testId)

	return &VaultInitializer{
		kubeClient: kubeClient,
		details:    details,

		rootMount:          rootMount,
		intermediateMount:  intermediateMount,
		role:               role,
		appRoleAuthPath:    appRoleAuthPath,
		kubernetesAuthPath: kubernetesAuthPath,
		clientCertAuthPath: clientCertAuthPath,

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

// AppRoleAuthPath returns the AppRole auth mount point in Vault.
// The format is "/v1/auth/xxxxx-auth-clientcert".
func (v *VaultInitializer) ClientCertificateAuthPath() string {
	return path.Join("/v1", "auth", v.clientCertAuthPath)
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

func NewVaultClientCertificateSecret(secretName string, certificate, key []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certificate,
			corev1.TLSPrivateKeyKey: key,
		},
		Type: corev1.SecretTypeTLS,
	}
}

// Set up a new Vault client, port-forward to the Vault instance.
func (v *VaultInitializer) Init(ctx context.Context) error {
	cfg := vault.DefaultConfiguration()
	cfg.Address = v.details.ProxyURL

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(v.details.VaultCA); !ok {
		return fmt.Errorf("error loading Vault CA bundle: %s", v.details.VaultCA)
	}
	cfg.HTTPClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = caCertPool
	if v.details.EnforceMtls {
		clientCertificate, err := tls.X509KeyPair(v.details.VaultClientCertificate, v.details.VaultClientPrivateKey)
		if err != nil {
			return fmt.Errorf("unable to read vault client certificate: %s", err)
		}
		cfg.HTTPClient.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{clientCertificate}
	}

	client, err := vault.New(vault.WithConfiguration(cfg))
	if err != nil {
		return fmt.Errorf("unable to initialize vault client: %s", err)
	}

	if err := client.SetToken(vaultToken); err != nil {
		return err
	}
	v.client = client

	// Wait for port-forward to be ready
	{
		proxyUrl, err := url.Parse(v.details.ProxyURL)
		if err != nil {
			return fmt.Errorf("error parsing proxy URL: %s", err.Error())
		}
		var lastError error
		// The timeout below must be aligned with the time taken by the Vault addons to start,
		// each addon safely takes about 20 seconds to start and two addons are started one after another,
		// one for without mTLS enforced and another with mTLS enforced
		err = wait.PollUntilContextTimeout(ctx, time.Second, 45*time.Second, true, func(ctx context.Context) (bool, error) {
			conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", proxyUrl.Host)
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
		err = wait.PollUntilContextTimeout(ctx, time.Second, 20*time.Second, true, func(ctx context.Context) (bool, error) {
			_, err := v.client.System.ReadHealthStatus(ctx)
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

// Set up a Vault PKI.
func (v *VaultInitializer) Setup(ctx context.Context) error {
	// Enable a new Vault secrets engine at v.RootMount
	if err := v.mountPKI(ctx, v.rootMount, "87600h"); err != nil {
		return err
	}

	// Generate a self-signed CA cert using the engine at v.RootMount
	rootCa, err := v.generateRootCert(ctx)
	if err != nil {
		return err
	}

	// Configure issuing certificate endpoints and CRL distribution points to be
	// set on certs issued by v.RootMount.
	if err := v.configureCert(ctx, v.rootMount); err != nil {
		return err

	}

	// Enable a new Vault secrets engine at v.intermediateMount
	if err := v.mountPKI(ctx, v.intermediateMount, "43800h"); err != nil {
		return err
	}

	// Generate a CSR for secrets engine at v.intermediateMount
	csr, err := v.generateIntermediateSigningReq(ctx)
	if err != nil {
		return err
	}

	// Issue a new intermediate CA from v.RootMount for the CSR created above.
	intermediateCa, err := v.signCertificate(ctx, csr)
	if err != nil {
		return err
	}

	// Set the engine at v.intermediateMount as an intermediateCA using the cert
	// issued by v.RootMount, above and optionally the root CA cert.
	caChain := intermediateCa
	if v.configureWithRoot {
		caChain = fmt.Sprintf("%s\n%s", intermediateCa, rootCa)
	}
	if err := v.importSignIntermediate(ctx, caChain, v.intermediateMount); err != nil {
		return err
	}

	// Configure issuing certificate endpoints and CRL distribution points to be
	// set on certs issued by v.intermediateMount.
	if err := v.configureCert(ctx, v.intermediateMount); err != nil {
		return err
	}

	if err := v.configureIntermediateRoles(ctx); err != nil {
		return err
	}

	if v.appRoleAuthPath != "" {
		if err := v.setupAppRoleAuth(ctx); err != nil {
			return err
		}
	}

	if v.kubernetesAuthPath != "" {
		if err := v.setupKubernetesBasedAuth(ctx); err != nil {
			return err
		}
	}

	if v.clientCertAuthPath != "" {
		if err := v.setupClientCertAuth(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (v *VaultInitializer) Clean(ctx context.Context) error {
	if _, err := v.client.System.MountsDisableSecretsEngine(ctx, "/"+v.intermediateMount); err != nil {
		return fmt.Errorf("unable to unmount %v: %v", v.intermediateMount, err)
	}
	if _, err := v.client.System.MountsDisableSecretsEngine(ctx, "/"+v.rootMount); err != nil {
		return fmt.Errorf("unable to unmount %v: %v", v.rootMount, err)
	}

	return nil
}

func (v *VaultInitializer) CreateAppRole(ctx context.Context) (string, string, error) {
	// create policy
	policy := fmt.Sprintf(`path "%s" { capabilities = [ "create", "update" ] }`, v.IntermediateSignPath())
	_, err := v.client.System.PoliciesWriteAclPolicy(
		ctx,
		v.role,
		schema.PoliciesWriteAclPolicyRequest{
			Policy: policy,
		},
	)
	if err != nil {
		return "", "", fmt.Errorf("error creating policy: %s", err.Error())
	}

	// # create approle
	_, err = v.client.Auth.AppRoleWriteRole(
		ctx,
		v.role,
		schema.AppRoleWriteRoleRequest{
			TokenPeriod:   "24h",
			TokenPolicies: []string{v.role},
		},
		vault.WithMountPath(v.appRoleAuthPath),
	)
	if err != nil {
		return "", "", fmt.Errorf("error creating approle: %s", err.Error())
	}

	// # read the role-id
	respRoleId, err := v.client.Auth.AppRoleReadRoleId(
		ctx,
		v.role,
		vault.WithMountPath(v.appRoleAuthPath),
	)
	if err != nil {
		return "", "", fmt.Errorf("error reading role_id: %s", err.Error())
	}

	// # read the secret-id
	// TODO: Should use Auth.AppRoleWriteSecretId instead of raw write here,
	// but it's currently broken. See:
	// https://github.com/hashicorp/vault-client-go/issues/249
	resp, err := v.client.Write(ctx, "/v1/auth/"+v.appRoleAuthPath+"/role/"+v.role+"/secret-id", nil)
	if err != nil {
		return "", "", fmt.Errorf("error reading secret_id: %s", err.Error())
	}
	return respRoleId.Data.RoleId, resp.Data["secret_id"].(string), nil
}

func (v *VaultInitializer) CleanAppRole(ctx context.Context) error {
	_, err := v.client.Auth.AppRoleDeleteRole(
		ctx,
		v.role,
		vault.WithMountPath(v.appRoleAuthPath),
	)
	if err != nil {
		return fmt.Errorf("error deleting AppRole: %s", err.Error())
	}

	_, err = v.client.System.PoliciesDeleteAclPolicy(ctx, v.role)
	if err != nil {
		return fmt.Errorf("error deleting policy: %s", err.Error())
	}

	return nil
}

func (v *VaultInitializer) mountPKI(ctx context.Context, mount, ttl string) error {
	_, err := v.client.System.MountsEnableSecretsEngine(
		ctx,
		"/"+mount,
		schema.MountsEnableSecretsEngineRequest{
			Type: "pki",
			Config: map[string]interface{}{
				"max_lease_ttl": ttl,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("error mounting %s: %s", mount, err.Error())
	}

	return nil
}

func (v *VaultInitializer) generateRootCert(ctx context.Context) (string, error) {
	resp, err := v.client.Secrets.PkiGenerateRoot(
		ctx,
		"internal",
		schema.PkiGenerateRootRequest{
			CommonName:        "Root CA",
			Ttl:               "87600h",
			ExcludeCnFromSans: true,
			KeyType:           "ec",
			KeyBits:           256,
		},
		vault.WithMountPath(v.rootMount),
	)
	if err != nil {
		return "", fmt.Errorf("error generating CA root certificate: %s", err.Error())
	}
	return resp.Data.Certificate, nil
}

func (v *VaultInitializer) generateIntermediateSigningReq(ctx context.Context) (string, error) {
	resp, err := v.client.Secrets.PkiGenerateIntermediate(
		ctx,
		"internal",
		schema.PkiGenerateIntermediateRequest{
			CommonName:        "Intermediate CA",
			Ttl:               "43800h",
			ExcludeCnFromSans: true,
			KeyType:           "ec",
			KeyBits:           256,
		},
		vault.WithMountPath(v.intermediateMount),
	)
	if err != nil {
		return "", fmt.Errorf("error generating CA intermediate certificate: %s", err.Error())
	}

	return resp.Data.Csr, nil
}

func (v *VaultInitializer) signCertificate(ctx context.Context, csr string) (string, error) {
	resp, err := v.client.Secrets.PkiRootSignIntermediate(
		ctx,
		schema.PkiRootSignIntermediateRequest{
			UseCsrValues:      true,
			Ttl:               "43800h",
			ExcludeCnFromSans: true,
			Csr:               csr,
		},
		vault.WithMountPath(v.rootMount),
	)
	if err != nil {
		return "", fmt.Errorf("error signing intermediate Vault certificate: %s", err.Error())
	}

	return resp.Data.Certificate, nil
}

func (v *VaultInitializer) importSignIntermediate(ctx context.Context, caChain, intermediateMount string) error {
	_, err := v.client.Secrets.PkiSetSignedIntermediate(
		ctx,
		schema.PkiSetSignedIntermediateRequest{
			Certificate: caChain,
		},
		vault.WithMountPath(intermediateMount),
	)
	if err != nil {
		return fmt.Errorf("error importing intermediate Vault certificate: %s", err.Error())
	}

	return nil
}

func (v *VaultInitializer) configureCert(ctx context.Context, mount string) error {
	_, err := v.client.Secrets.PkiConfigureUrls(
		ctx,
		schema.PkiConfigureUrlsRequest{
			IssuingCertificates: []string{
				fmt.Sprintf("https://vault.vault:8200/v1/%s/ca", mount),
			},
			CrlDistributionPoints: []string{
				fmt.Sprintf("https://vault.vault:8200/v1/%s/crl", mount),
			},
		},
		vault.WithMountPath(mount),
	)
	if err != nil {
		return fmt.Errorf("error configuring Vault certificate: %s", err.Error())
	}

	return nil
}

func (v *VaultInitializer) configureIntermediateRoles(ctx context.Context) error {
	// TODO: Should use Secrets.PkiWriteRole here,
	// but it is broken. See:
	// https://github.com/hashicorp/vault-client-go/issues/195
	params := map[string]interface{}{
		"allow_any_name":     "true",
		"max_ttl":            "2160h",
		"key_type":           "any",
		"require_cn":         "false",
		"allowed_other_sans": "*",
		"use_csr_sans":       "true",
		"allowed_uri_sans":   "spiffe://cluster.local/*",
		"enforce_hostnames":  "false",
		"allow_bare_domains": "true",
	}
	url := path.Join("/v1", v.intermediateMount, "roles", v.role)

	_, err := v.client.Write(ctx, url, params)
	if err != nil {
		return fmt.Errorf("error creating role %s: %s", v.role, err.Error())
	}

	return nil
}

func (v *VaultInitializer) setupAppRoleAuth(ctx context.Context) error {
	// vault auth-enable approle
	resp, err := v.client.System.AuthListEnabledMethods(ctx)
	if err != nil {
		return fmt.Errorf("error fetching auth mounts: %s", err.Error())
	}

	if _, ok := resp.Data[v.appRoleAuthPath]; ok {
		return nil
	}

	_, err = v.client.System.AuthEnableMethod(
		ctx,
		v.appRoleAuthPath,
		schema.AuthEnableMethodRequest{
			Type: "approle",
		},
	)
	if err != nil {
		return fmt.Errorf("error enabling approle auth: %s", err.Error())
	}

	return nil
}

func (v *VaultInitializer) setupKubernetesBasedAuth(ctx context.Context) error {
	// vault auth-enable kubernetes
	resp, err := v.client.System.AuthListEnabledMethods(ctx)
	if err != nil {
		return fmt.Errorf("error fetching auth mounts: %s", err.Error())
	}

	if _, ok := resp.Data[v.kubernetesAuthPath]; ok {
		return nil
	}

	_, err = v.client.System.AuthEnableMethod(
		ctx,
		v.kubernetesAuthPath,
		schema.AuthEnableMethodRequest{
			Type: "kubernetes",
		},
	)
	if err != nil {
		return fmt.Errorf("error enabling kubernetes auth: %s", err.Error())
	}

	// vault write auth/kubernetes/config
	_, err = v.client.Auth.KubernetesConfigureAuth(
		ctx,
		schema.KubernetesConfigureAuthRequest{
			KubernetesHost: v.kubernetesAPIServerURL,
			// Since Vault 1.9, HashiCorp recommends disabling the iss validation.
			// If we don't disable the iss validation, we can't use the same
			// Kubernetes auth config for both testing the "secretRef" Kubernetes
			// auth and the "serviceAccountRef" Kubernetes auth because the former
			// relies on static tokens for which "iss" is
			// "kubernetes/serviceaccount", and the latter relies on bound tokens for
			// which "iss" is "https://kubernetes.default.svc.cluster.local".
			// https://www.vaultproject.io/docs/auth/kubernetes#kubernetes-1-21
			DisableIssValidation: true,
		},
		vault.WithMountPath(v.kubernetesAuthPath),
	)
	if err != nil {
		return fmt.Errorf("error configuring kubernetes auth backend: %s", err.Error())
	}

	return nil
}

// CreateKubernetesRole creates a service account and ClusterRoleBinding for
// Kubernetes auth delegation. The name "boundSA" refers to the Vault param
// "bound_service_account_names".
func (v *VaultInitializer) CreateKubernetesRole(ctx context.Context, client kubernetes.Interface, boundNS, boundSA string) error {
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: boundSA,
		},
	}
	_, err := client.CoreV1().ServiceAccounts(boundNS).Create(ctx, serviceAccount, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating ServiceAccount for Kubernetes auth: %s", err.Error())
	}

	// create policy
	policy := fmt.Sprintf(`path "%s" { capabilities = [ "create", "update" ] }`, v.IntermediateSignPath())
	_, err = v.client.System.PoliciesWriteAclPolicy(
		ctx,
		v.role,
		schema.PoliciesWriteAclPolicyRequest{
			Policy: policy,
		},
	)
	if err != nil {
		return fmt.Errorf("error creating policy: %s", err.Error())
	}

	// # create approle
	_, err = v.client.Auth.KubernetesWriteAuthRole(
		ctx,
		v.role,
		schema.KubernetesWriteAuthRoleRequest{
			Period:                        "24h",
			Policies:                      []string{v.role},
			BoundServiceAccountNames:      []string{boundSA},
			BoundServiceAccountNamespaces: []string{boundNS},
		},
		vault.WithMountPath(v.kubernetesAuthPath),
	)
	if err != nil {
		return fmt.Errorf("error creating kubernetes role: %s", err.Error())
	}

	return nil
}

func (v *VaultInitializer) IntermediateSignPath() string {
	return path.Join(v.intermediateMount, "sign", v.role)
}

// CleanKubernetesRole cleans up the ClusterRoleBinding and ServiceAccount for Kubernetes auth delegation
func (v *VaultInitializer) CleanKubernetesRole(ctx context.Context, client kubernetes.Interface, boundNS, boundSA string) error {
	if err := client.CoreV1().ServiceAccounts(boundNS).Delete(ctx, boundSA, metav1.DeleteOptions{}); err != nil {
		return err
	}

	// vault delete auth/kubernetes/role/<roleName>
	_, err := v.client.Auth.KubernetesDeleteAuthRole(ctx, v.role, vault.WithMountPath(v.kubernetesAuthPath))
	if err != nil {
		return fmt.Errorf("error cleaning up kubernetes auth role: %s", err.Error())
	}

	_, err = v.client.System.PoliciesDeleteAclPolicy(ctx, v.role)
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
func CreateKubernetesRoleForServiceAccountRefAuth(ctx context.Context, client kubernetes.Interface, roleName, saNS, saName string) error {
	role, binding := RoleAndBindingForServiceAccountRefAuth(roleName, saNS, saName)
	_, err := client.RbacV1().Roles(saNS).Create(ctx, role, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating Role for Kubernetes auth ServiceAccount with serviceAccountRef: %s", err.Error())
	}
	_, err = client.RbacV1().RoleBindings(saNS).Create(ctx, binding, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating RoleBinding for Kubernetes auth ServiceAccount with serviceAccountRef: %s", err.Error())
	}

	return nil
}

func CleanKubernetesRoleForServiceAccountRefAuth(ctx context.Context, client kubernetes.Interface, roleName, saNS, saName string) error {
	if err := client.RbacV1().RoleBindings(saNS).Delete(ctx, roleName, metav1.DeleteOptions{}); err != nil {
		return err
	}

	if err := client.RbacV1().Roles(saNS).Delete(ctx, roleName, metav1.DeleteOptions{}); err != nil {
		return err
	}

	return nil
}

func (v *VaultInitializer) setupClientCertAuth(ctx context.Context) error {
	// vault auth-enable cert
	resp, err := v.client.System.AuthListEnabledMethods(ctx)
	if err != nil {
		return fmt.Errorf("error fetching auth mounts: %s", err.Error())
	}

	if _, ok := resp.Data[v.clientCertAuthPath]; ok {
		return nil
	}

	_, err = v.client.System.AuthEnableMethod(
		ctx,
		v.clientCertAuthPath,
		schema.AuthEnableMethodRequest{
			Type: "cert",
		},
	)
	if err != nil {
		return fmt.Errorf("error enabling cert auth: %s", err.Error())
	}

	return nil
}

func (v *VaultInitializer) CreateClientCertRole(ctx context.Context) (key []byte, cert []byte, _ error) {
	privateKey, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certificateBytes, err := x509.CreateCertificate(cmrand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes})
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateBytes})

	role_path := v.IntermediateSignPath()
	policy := fmt.Sprintf(`path "%s" { capabilities = [ "create", "update" ] } `, role_path)
	_, err = v.client.System.PoliciesWriteAclPolicy(
		ctx,
		v.role,
		schema.PoliciesWriteAclPolicyRequest{
			Policy: policy,
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating policy: %s", err.Error())
	}

	// vault write auth/cert/certs/web
	_, err = v.client.Auth.CertWriteCertificate(
		ctx,
		v.role,
		schema.CertWriteCertificateRequest{
			DisplayName:   v.role,
			Certificate:   string(certificatePEM),
			TokenPolicies: []string{v.role},
			TokenTtl:      "3600",
		},
		vault.WithMountPath(v.clientCertAuthPath),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating cert auth role: %s", err.Error())
	}

	return privateKeyPEM, certificatePEM, nil
}
