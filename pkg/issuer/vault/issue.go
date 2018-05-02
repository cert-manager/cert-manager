package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/golang/glog"
	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/certutil"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	errorGetCertKeyPair = "ErrGetCertKeyPair"
	errorIssueCert      = "ErrIssueCert"

	successCertIssued = "CertIssueSuccess"

	messageErrorIssueCert = "Error issuing TLS certificate: "

	messageCertIssued = "Certificate issued successfully"

	defaultCertificateDuration = time.Hour * 24 * 90
)

const (
	defaultOrganization = "cert-manager"

	keyBitSize = 2048
)

func (v *Vault) Issue(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	key, certPem, err := v.obtainCertificate(ctx, crt)
	if err != nil {
		s := messageErrorIssueCert + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueCert, s, false)
		return nil, nil, err
	}

	crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, successCertIssued, messageCertIssued, true)

	return key, certPem, nil
}

func (v *Vault) obtainCertificate(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	// get existing certificate private key
	signeeKey, err := kube.SecretTLSKey(v.secretsLister, crt.Namespace, crt.Spec.SecretName)
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		signeeKey, err = pki.GenerateRSAPrivateKey(keyBitSize)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating private key: %s", err.Error())
		}
	}

	if err != nil {
		return nil, nil, fmt.Errorf("error getting certificate private key: %s", err.Error())
	}

	commonName := crt.Spec.CommonName
	altNames := crt.Spec.DNSNames
	if len(commonName) == 0 && len(altNames) == 0 {
		return nil, nil, fmt.Errorf("no domains specified on certificate")
	}

	crtPem, err := v.signCertificate(crt, signeeKey)
	if err != nil {
		return nil, nil, err
	}

	return pki.EncodePKCS1PrivateKey(signeeKey), crtPem, nil
}

// signCertificate returns a signed x509.Certificate object for the given
// *v1alpha1.Certificate crt.
func (v *Vault) signCertificate(crt *v1alpha1.Certificate, key *rsa.PrivateKey) ([]byte, error) {
	commonName := pki.CommonNameForCertificate(crt)
	altNames := pki.DNSNamesForCertificate(crt)

	if len(commonName) == 0 && len(altNames) > 0 {
		commonName = altNames[0]
	}

	template := pki.GenerateCSR(commonName, altNames...)
	template.Subject.Organization = []string{defaultOrganization}

	derBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("error creating x509 certificate: %s", err.Error())
	}

	pemRequestBuf := &bytes.Buffer{}
	err = pem.Encode(pemRequestBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: derBytes})
	if err != nil {
		return nil, fmt.Errorf("error encoding certificate request: %s", err.Error())
	}

	return v.requestVaultCert(commonName, altNames, pemRequestBuf.String())
}

func (v *Vault) initVaultClient() (*vault.Client, error) {
	client, err := vault.NewClient(nil)
	if err != nil {
		return nil, fmt.Errorf("error initializing Vault client: %s", err.Error())
	}

	client.SetAddress(v.issuer.GetSpec().Vault.Server)

	tokenRef := v.issuer.GetSpec().Vault.Auth.TokenSecretRef
	if tokenRef.Name != "" {
		token, err := v.vaultTokenRef(tokenRef.Name, tokenRef.Key)
		if err != nil {
			return nil, fmt.Errorf("error reading Vault token from secret %s/%s: %s", v.issuerResourcesNamespace, tokenRef.Name, err.Error())
		}
		client.SetToken(token)

		return client, nil
	}

	appRole := v.issuer.GetSpec().Vault.Auth.AppRole
	if appRole.RoleId != "" {
		token, err := v.requestTokenWithAppRoleRef(client, &appRole)
		if err != nil {
			return nil, fmt.Errorf("error reading Vault token from secret %s/%s: %s", v.issuerResourcesNamespace, appRole.SecretRef.Name, err.Error())
		}
		client.SetToken(token)

		return client, nil
	}

	return nil, fmt.Errorf("error initializing Vault client. tokenSecretRef or appRoleSecretRef not set")
}

func (v *Vault) requestTokenWithAppRoleRef(client *vault.Client, appRole *v1alpha1.VaultAppRole) (string, error) {
	roleId, secretId, err := v.appRoleRef(appRole)
	if err != nil {
		return "", fmt.Errorf("error reading Vault AppRole from secret: %s/%s: %s", appRole.SecretRef.Name, v.issuerResourcesNamespace, err.Error())
	}

	parameters := map[string]string{
		"role_id":   roleId,
		"secret_id": secretId,
	}

	url := "/v1/auth/approle/login"

	request := client.NewRequest("POST", url)

	err = request.SetJSONBody(parameters)
	if err != nil {
		return "", fmt.Errorf("error encoding Vault parameters: %s", err.Error())
	}

	resp, err := client.RawRequest(request)
	if err != nil {
		return "", fmt.Errorf("error calling Vault server: %s", err.Error())
	}

	defer resp.Body.Close()

	vaultResult := vault.Secret{}
	resp.DecodeJSON(&vaultResult)
	if err != nil {
		return "", fmt.Errorf("unable to decode JSON payload: %s", err.Error())
	}

	token, err := vaultResult.TokenID()
	if err != nil {
		return "", fmt.Errorf("unable to read token: %s", err.Error())
	}

	return token, nil
}

func (v *Vault) requestVaultCert(commonName string, altNames []string, csr string) ([]byte, error) {
	client, err := v.initVaultClient()
	if err != nil {
		return nil, err
	}

	glog.V(4).Infof("Vault certificate request for commonName %s altNames: %q", commonName, altNames)

	parameters := map[string]string{
		"common_name": commonName,
		"alt_names":   strings.Join(altNames, ","),
		"ttl":         defaultCertificateDuration.String(),
		"csr":         csr,
		"exclude_cn_from_sans": "true",
	}

	url := path.Join("/v1", v.issuer.GetSpec().Vault.Path)

	request := client.NewRequest("POST", url)

	err = request.SetJSONBody(parameters)
	if err != nil {
		return nil, fmt.Errorf("error encoding Vault parameters: %s", err.Error())
	}

	resp, err := client.RawRequest(request)
	if err != nil {
		return nil, fmt.Errorf("error calling Vault server: %s", err.Error())
	}

	defer resp.Body.Close()

	vaultResult := certutil.Secret{}
	resp.DecodeJSON(&vaultResult)
	if err != nil {
		return nil, fmt.Errorf("unable to decode JSON payload: %s", err.Error())
	}

	parsedBundle, err := certutil.ParsePKIMap(vaultResult.Data)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate: %s", err.Error())
	}

	bundle, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, fmt.Errorf("unable to convert certificate bundle to PEM bundle: %s", err.Error())
	}

	return []byte(bundle.ToPEMBundle()), nil
}

func (v *Vault) appRoleRef(appRole *v1alpha1.VaultAppRole) (roleId, secretId string, err error) {
	roleId = strings.TrimSpace(appRole.RoleId)

	secret, err := v.secretsLister.Secrets(v.issuerResourcesNamespace).Get(appRole.SecretRef.Name)
	if err != nil {
		return "", "", err
	}

	key := "secretId"
	if appRole.SecretRef.Key != "secretId" {
		key = appRole.SecretRef.Key
	}

	keyBytes, ok := secret.Data[key]
	if !ok {
		return "", "", fmt.Errorf("no data for %q in secret '%s/%s'", key, appRole.SecretRef.Name, v.issuerResourcesNamespace)
	}

	secretId = string(keyBytes)
	secretId = strings.TrimSpace(secretId)

	return roleId, secretId, nil
}

func (v *Vault) vaultTokenRef(name, key string) (string, error) {
	secret, err := v.secretsLister.Secrets(v.issuerResourcesNamespace).Get(name)
	if err != nil {
		return "", err
	}

	if key == "" {
		key = "token"
	}

	keyBytes, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("no data for %q in secret '%s/%s'", key, name, v.issuerResourcesNamespace)
	}

	token := string(keyBytes)
	token = strings.TrimSpace(token)

	return token, nil
}
