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
	"errors"
	"fmt"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmerrors "github.com/cert-manager/cert-manager/pkg/util/errors"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

var _ Interface = &Vault{}

// ClientBuilder is a function type that returns a new Interface.
// Can be used in tests to create a mock signer of Vault certificate requests.
type ClientBuilder func(ctx context.Context, namespace string, _ func(ns string) CreateToken, _ internalinformers.SecretLister, _ v1.GenericIssuer) (Interface, error)

// Interface implements various high level functionality related to connecting
// with a Vault server, verifying its status and signing certificate request for
// Vault's certificate.
type Interface interface {
	Sign(csrPEM []byte, duration time.Duration) (certPEM []byte, caPEM []byte, err error)
	IsVaultInitializedAndUnsealed() error
}

// Client implements functionality to talk to a Vault server.
type Client interface {
	NewRequest(method, requestPath string) *vault.Request
	RawRequest(r *vault.Request) (*vault.Response, error)
	SetToken(v string)
}

// For mocking purposes.
type CreateToken func(ctx context.Context, saName string, req *authv1.TokenRequest, opts metav1.CreateOptions) (*authv1.TokenRequest, error)

// Vault implements Interface and holds a Vault issuer, secrets lister and a
// Vault client.
type Vault struct {
	createToken   CreateToken // Uses the same namespace as below.
	secretsLister internalinformers.SecretLister
	issuer        v1.GenericIssuer
	namespace     string

	// The pattern below, of namespaced and non-namespaced Vault clients, is copied from Hashicorp Nomad:
	// https://github.com/hashicorp/nomad/blob/6e4410a9b13ce167bc7ef53da97c621b5c9dcd12/nomad/vault.go#L180-L190

	// client is the Vault API client used for Namespace-relative integrations
	// with the Vault API (anything except `/v1/sys`).
	// The namespace feature is only available in Vault Enterprise.
	// The namespace HTTP header (X-Vault-Namespace) is ignored by the open source version of Vault.
	// See https://www.vaultproject.io/docs/enterprise/namespaces
	client Client

	// clientSys is the Vault API client used for non-Namespace-relative integrations
	// with the Vault API (anything involving `/v1/sys`). This client is never configured
	// with a Vault namespace, because these endpoints may return errors if a namespace
	// header is provided
	// See https://developer.hashicorp.com/vault/docs/enterprise/namespaces#root-only-api-paths
	clientSys Client
}

// New returns a new Vault instance with the given namespace, issuer and
// secrets lister.
// Returned errors may be network failures and should be considered for
// retrying.
func New(ctx context.Context, namespace string, createTokenFn func(ns string) CreateToken, secretsLister internalinformers.SecretLister, issuer v1.GenericIssuer) (Interface, error) {
	v := &Vault{
		createToken:   createTokenFn(namespace),
		secretsLister: secretsLister,
		namespace:     namespace,
		issuer:        issuer,
	}

	cfg, err := v.newConfig()
	if err != nil {
		return nil, err
	}

	client, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("error initializing Vault client: %s", err.Error())
	}

	// Set the Vault namespace.
	// An empty namespace string will cause the client to not send the namespace related HTTP headers to Vault.
	clientNS := client.WithNamespace(issuer.GetSpec().Vault.Namespace)

	// Use the (maybe) namespaced client to authenticate.
	// If a Vault namespace is configured, then the authentication endpoints are
	// expected to be in that namespace.
	if err := v.setToken(ctx, clientNS); err != nil {
		return nil, err
	}

	// A client for use with namespaced API paths
	v.client = clientNS

	// Create duplicate Vault client without a namespace, for interacting with root-only API paths.
	// For backwards compatibility, this client will use the token from the namespaced client,
	// although this is probably unnecessary / bad practice, since we only
	// interact with the sys/health endpoint which is an unauthenticated endpoint:
	// https://github.com/hashicorp/vault/issues/209#issuecomment-102485565.
	v.clientSys = clientNS.WithNamespace("")

	return v, nil
}

// Sign will connect to a Vault instance to sign a certificate signing request.
func (v *Vault) Sign(csrPEM []byte, duration time.Duration) (cert []byte, ca []byte, err error) {
	csr, err := pki.DecodeX509CertificateRequestBytes(csrPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode CSR for signing: %s", err)
	}

	parameters := map[string]string{
		"common_name": csr.Subject.CommonName,
		"alt_names":   strings.Join(csr.DNSNames, ","),
		"ip_sans":     strings.Join(pki.IPAddressesToString(csr.IPAddresses), ","),
		"uri_sans":    strings.Join(pki.URLsToString(csr.URIs), ","),
		"ttl":         duration.String(),
		"csr":         string(csrPEM),

		"exclude_cn_from_sans": "true",
	}

	vaultIssuer := v.issuer.GetSpec().Vault
	url := path.Join("/v1", vaultIssuer.Path)

	request := v.client.NewRequest("POST", url)

	if err := request.SetJSONBody(parameters); err != nil {
		return nil, nil, fmt.Errorf("failed to build vault request: %s", err)
	}

	resp, err := v.client.RawRequest(request)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign certificate by vault: %s", err)
	}

	defer resp.Body.Close()

	vaultResult := certutil.Secret{}
	err = resp.DecodeJSON(&vaultResult)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode response returned by vault: %s", err)
	}

	return extractCertificatesFromVaultCertificateSecret(&vaultResult)
}

func (v *Vault) setToken(ctx context.Context, client Client) error {
	// IMPORTANT: Because of backwards compatibility with older versions that
	// incorrectly allowed multiple authentication methods to be specified at
	// the time of validation, we must still allow multiple authentication methods
	// to be specified.
	// In terms of implementation, we will use the first authentication method.
	// The order of precedence is: tokenSecretRef, appRole, kubernetes

	tokenRef := v.issuer.GetSpec().Vault.Auth.TokenSecretRef
	if tokenRef != nil {
		token, err := v.tokenRef(tokenRef.Name, v.namespace, tokenRef.Key)
		if err != nil {
			return err
		}
		client.SetToken(token)

		return nil
	}

	appRole := v.issuer.GetSpec().Vault.Auth.AppRole
	if appRole != nil {
		token, err := v.requestTokenWithAppRoleRef(client, appRole)
		if err != nil {
			return err
		}
		client.SetToken(token)

		return nil
	}

	kubernetesAuth := v.issuer.GetSpec().Vault.Auth.Kubernetes
	if kubernetesAuth != nil {
		token, err := v.requestTokenWithKubernetesAuth(ctx, client, kubernetesAuth)
		if err != nil {
			return fmt.Errorf("while requesting a Vault token using the Kubernetes auth: %w", err)
		}
		client.SetToken(token)
		return nil
	}

	return cmerrors.NewInvalidData("error initializing Vault client: tokenSecretRef, appRoleSecretRef, or Kubernetes auth role not set")
}

func (v *Vault) newConfig() (*vault.Config, error) {
	cfg := vault.DefaultConfig()
	cfg.Address = v.issuer.GetSpec().Vault.Server

	caBundle, err := v.caBundle()
	if err != nil {
		return nil, fmt.Errorf("failed to load vault CA bundle: %w", err)
	}

	if len(caBundle) != 0 {
		caCertPool := x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(caBundle)
		if !ok {
			return nil, fmt.Errorf("no Vault CA bundles loaded, check bundle contents")
		}

		cfg.HttpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = caCertPool
	}

	clientCertificate, err := v.clientCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to load vault client certificate: %w", err)
	}

	if clientCertificate != nil {
		cfg.HttpClient.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{*clientCertificate}
	}

	return cfg, nil
}

// caBundle returns the CA bundle for the Vault server. Can be used in Vault
// client configs to trust the connection to the Vault server. If no custom CA
// bundle is configured, an empty byte slice is returned.
// Assumes the in-line and Secret CA bundles are not both defined.
// If the `key` of the Secret CA bundle is not defined, its value defaults to
// `ca.crt`.
func (v *Vault) caBundle() ([]byte, error) {
	if len(v.issuer.GetSpec().Vault.CABundle) > 0 {
		return v.issuer.GetSpec().Vault.CABundle, nil
	}

	ref := v.issuer.GetSpec().Vault.CABundleSecretRef
	if ref == nil {
		return nil, nil
	}

	secret, err := v.secretsLister.Secrets(v.namespace).Get(ref.Name)
	if err != nil {
		return nil, fmt.Errorf("could not access secret '%s/%s': %s", v.namespace, ref.Name, err)
	}

	var key string
	if ref.Key != "" {
		key = ref.Key
	} else {
		key = cmmeta.TLSCAKey
	}

	certBytes, ok := secret.Data[key]
	if !ok {
		return nil, fmt.Errorf("no data for %q in secret '%s/%s'", key, v.namespace, ref.Name)
	}

	return certBytes, nil
}

// clientCertificate returns the Client Certificate for the Vault server.
// Can be used in Vault client configs when the server requires mTLS.
func (v *Vault) clientCertificate() (*tls.Certificate, error) {
	refCert := v.issuer.GetSpec().Vault.ClientCertSecretRef
	refPrivateKey := v.issuer.GetSpec().Vault.ClientKeySecretRef
	if refCert == nil || refPrivateKey == nil {
		return nil, nil
	}

	secretCert, err := v.secretsLister.Secrets(v.namespace).Get(refCert.Name)
	if err != nil {
		return nil, fmt.Errorf("could not access Secret '%s/%s': %s", v.namespace, refCert.Name, err)
	}
	secretPrivateKey, err := v.secretsLister.Secrets(v.namespace).Get(refPrivateKey.Name)
	if err != nil {
		return nil, fmt.Errorf("could not access Secret '%s/%s': %s", v.namespace, refPrivateKey.Name, err)
	}

	var keyCert string
	if refCert.Key != "" {
		keyCert = refCert.Key
	} else {
		keyCert = corev1.TLSCertKey
	}

	var keyPrivate string
	if refPrivateKey.Key != "" {
		keyPrivate = refPrivateKey.Key
	} else {
		keyPrivate = corev1.TLSPrivateKeyKey
	}

	certBytes, ok := secretCert.Data[keyCert]
	if !ok {
		return nil, fmt.Errorf("no data for %q in Secret '%s/%s'", keyCert, v.namespace, refCert.Name)
	}
	privateKeyBytes, ok := secretPrivateKey.Data[keyPrivate]
	if !ok {
		return nil, fmt.Errorf("no data for %q in Secret '%s/%s'", keyPrivate, v.namespace, refPrivateKey.Name)
	}

	cert, err := tls.X509KeyPair(certBytes, privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse the TLS certificate from Secrets '%s/%s'(cert) and '%s/%s'(key): %s", v.namespace, refCert.Name, v.namespace, refPrivateKey.Name, err)
	}
	return &cert, nil
}

func (v *Vault) tokenRef(name, namespace, key string) (string, error) {
	secret, err := v.secretsLister.Secrets(namespace).Get(name)
	if err != nil {
		return "", err
	}

	if key == "" {
		key = v1.DefaultVaultTokenAuthSecretKey
	}

	keyBytes, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("no data for %q in secret '%s/%s'", key, name, namespace)
	}

	token := string(keyBytes)
	token = strings.TrimSpace(token)

	return token, nil
}

func (v *Vault) appRoleRef(appRole *v1.VaultAppRole) (roleId, secretId string, err error) {
	roleId = strings.TrimSpace(appRole.RoleId)

	secret, err := v.secretsLister.Secrets(v.namespace).Get(appRole.SecretRef.Name)
	if err != nil {
		return "", "", err
	}

	key := appRole.SecretRef.Key

	keyBytes, ok := secret.Data[key]
	if !ok {
		return "", "", fmt.Errorf("no data for %q in secret '%s/%s'", key, v.namespace, appRole.SecretRef.Name)
	}

	secretId = string(keyBytes)
	secretId = strings.TrimSpace(secretId)

	return roleId, secretId, nil
}

func (v *Vault) requestTokenWithAppRoleRef(client Client, appRole *v1.VaultAppRole) (string, error) {
	roleId, secretId, err := v.appRoleRef(appRole)
	if err != nil {
		return "", err
	}

	parameters := map[string]string{
		"role_id":   roleId,
		"secret_id": secretId,
	}

	authPath := appRole.Path
	if authPath == "" {
		authPath = "approle"
	}

	url := path.Join("/v1", "auth", authPath, "login")

	request := client.NewRequest("POST", url)

	err = request.SetJSONBody(parameters)
	if err != nil {
		return "", fmt.Errorf("error encoding Vault parameters: %s", err.Error())
	}

	resp, err := client.RawRequest(request)
	if err != nil {
		return "", fmt.Errorf("error logging in to Vault server: %s", err.Error())
	}

	defer resp.Body.Close()

	vaultResult := vault.Secret{}
	if err := resp.DecodeJSON(&vaultResult); err != nil {
		return "", fmt.Errorf("unable to decode JSON payload: %s", err.Error())
	}

	token, err := vaultResult.TokenID()
	if err != nil {
		return "", fmt.Errorf("unable to read token: %s", err.Error())
	}

	if token == "" {
		return "", errors.New("no token returned")
	}

	return token, nil
}

func (v *Vault) requestTokenWithKubernetesAuth(ctx context.Context, client Client, kubernetesAuth *v1.VaultKubernetesAuth) (string, error) {
	var jwt string
	switch {
	case kubernetesAuth.SecretRef.Name != "":
		secret, err := v.secretsLister.Secrets(v.namespace).Get(kubernetesAuth.SecretRef.Name)
		if err != nil {
			return "", err
		}

		key := kubernetesAuth.SecretRef.Key
		if key == "" {
			key = v1.DefaultVaultTokenAuthSecretKey
		}

		keyBytes, ok := secret.Data[key]
		if !ok {
			return "", fmt.Errorf("no data for %q in secret '%s/%s'", key, v.namespace, kubernetesAuth.SecretRef.Name)
		}

		jwt = string(keyBytes)

	case kubernetesAuth.ServiceAccountRef != nil:
		defaultAudience := "vault://"
		if v.issuer.GetNamespace() != "" {
			defaultAudience += v.issuer.GetNamespace() + "/"
		}
		defaultAudience += v.issuer.GetName()

		audiences := append([]string(nil), kubernetesAuth.ServiceAccountRef.TokenAudiences...)
		audiences = append(audiences, defaultAudience)

		tokenrequest, err := v.createToken(ctx, kubernetesAuth.ServiceAccountRef.Name, &authv1.TokenRequest{
			Spec: authv1.TokenRequestSpec{
				// Default audience is generated by cert-manager.
				// This is the most secure configuration as vault role must explicitly mandate the audience.
				// The format is:
				//   "vault://<namespace>/<issuer-name>"   (for an Issuer)
				//   "vault://<issuer-name>"               (for a ClusterIssuer)
				//
				// If audiences are specified in the VaultIssuer, they will be appended to the default audience.
				//
				// Vault backend can bind the kubernetes auth backend role to the service account and specific namespace of the service account.
				// Providing additional audiences is not considered a major non-mitigatable security risk
				// as if someone creates an Issuer in another namespace/globally with the same audiences
				// in attempt to highjack the certificate vault (if role config mandates sa:namespace) won't authorise the connection
				// as token subject won't match vault role requirement to have SA originated from the specific namespace.
				Audiences: audiences,

				// Since the JWT is only used to authenticate with Vault and is
				// immediately discarded, let's use the minimal duration
				// possible. 10 minutes is the minimum allowed by the Kubernetes
				// API.
				ExpirationSeconds: ptr.To(int64(600)),
			},
		}, metav1.CreateOptions{})
		if err != nil {
			return "", fmt.Errorf("while requesting a token for the service account %s/%s: %s", v.issuer.GetNamespace(), kubernetesAuth.ServiceAccountRef.Name, err.Error())
		}

		jwt = tokenrequest.Status.Token
	default:
		return "", fmt.Errorf("programmer mistake: both serviceAccountRef and tokenRef.name are empty")
	}

	parameters := map[string]string{
		"role": kubernetesAuth.Role,
		"jwt":  jwt,
	}

	mountPath := kubernetesAuth.Path
	if mountPath == "" {
		mountPath = v1.DefaultVaultKubernetesAuthMountPath
	}

	url := filepath.Join(mountPath, "login")
	request := client.NewRequest("POST", url)
	err := request.SetJSONBody(parameters)
	if err != nil {
		return "", fmt.Errorf("error encoding Vault parameters: %s", err.Error())
	}

	resp, err := client.RawRequest(request)
	if err != nil {
		return "", fmt.Errorf("error calling Vault server: %s", err.Error())
	}

	defer resp.Body.Close()
	vaultResult := vault.Secret{}
	err = resp.DecodeJSON(&vaultResult)
	if err != nil {
		return "", fmt.Errorf("unable to decode JSON payload: %s", err.Error())
	}

	token, err := vaultResult.TokenID()
	if err != nil {
		return "", fmt.Errorf("unable to read token: %s", err.Error())
	}

	return token, nil
}

func extractCertificatesFromVaultCertificateSecret(secret *certutil.Secret) ([]byte, []byte, error) {
	parsedBundle, err := certutil.ParsePKIMap(secret.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode response returned by vault: %s", err)
	}

	vbundle, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to convert certificate bundle to PEM bundle: %s", err.Error())
	}

	bundle, err := pki.ParseSingleCertificateChainPEM([]byte(
		strings.Join(append(
			vbundle.CAChain,
			vbundle.IssuingCA,
			vbundle.Certificate,
		), "\n")))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate chain from vault: %w", err)
	}

	return bundle.ChainPEM, bundle.CAPEM, nil
}

func (v *Vault) IsVaultInitializedAndUnsealed() error {
	healthURL := path.Join("/v1", "sys", "health")
	healthRequest := v.clientSys.NewRequest("GET", healthURL)
	healthResp, err := v.clientSys.RawRequest(healthRequest)

	if healthResp != nil {
		defer healthResp.Body.Close()
	}

	// 200 = if initialized, unsealed, and active
	// 429 = if unsealed and standby
	// 472 = if disaster recovery mode replication secondary and active
	// 473 = if performance standby
	// 501 = if not initialized
	// 503 = if sealed
	// nolint: usestdlibvars // We use the numeric error codes here that we got from the Vault docs.
	if err != nil {
		switch {
		case healthResp == nil:
			return err
		case healthResp.StatusCode == 429, healthResp.StatusCode == 472, healthResp.StatusCode == 473:
			return nil
		case healthResp.StatusCode == 501:
			return fmt.Errorf("Vault is not initialized")
		case healthResp.StatusCode == 503:
			return fmt.Errorf("Vault is sealed")
		default:
			return fmt.Errorf("error calling Vault %s: %w", healthURL, err)
		}
	}

	return nil
}
