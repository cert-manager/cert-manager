package vault

import (
	"bytes"
	"context"
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
		signeeKey, err = pki.GeneratePrivateKeyForCertificate(crt)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating private key: %s", err.Error())
		}
	}

	if err != nil {
		return nil, nil, fmt.Errorf("error getting certificate private key: %s", err.Error())
	}

	template, err := pki.GenerateCSR(v.issuer, crt)
	if err != nil {
		return nil, nil, err
	}

	derBytes, err := pki.EncodeCSR(template, signeeKey)
	if err != nil {
		return nil, nil, err
	}

	pemRequestBuf := &bytes.Buffer{}
	err = pem.Encode(pemRequestBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: derBytes})
	if err != nil {
		return nil, nil, fmt.Errorf("error encoding certificate request: %s", err.Error())
	}

	crtBytes, err := v.requestVaultCert(template.Subject.CommonName, template.DNSNames, pemRequestBuf.Bytes())
	if err != nil {
		return nil, nil, err
	}

	keyBytes, err := pki.EncodePrivateKey(signeeKey)
	if err != nil {
		return nil, nil, err
	}

	return keyBytes, crtBytes, nil
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
			return nil, fmt.Errorf("error reading Vault token from secret %s/%s: %s", v.resourceNamespace, tokenRef.Name, err.Error())
		}
		client.SetToken(token)

		return client, nil
	}

	appRole := v.issuer.GetSpec().Vault.Auth.AppRole
	if appRole.RoleId != "" {
		token, err := v.requestTokenWithAppRoleRef(client, &appRole)
		if err != nil {
			return nil, fmt.Errorf("error reading Vault token from AppRole: %s", err.Error())
		}
		client.SetToken(token)

		return client, nil
	}

	return nil, fmt.Errorf("error initializing Vault client. tokenSecretRef or appRoleSecretRef not set")
}

func (v *Vault) requestTokenWithAppRoleRef(client *vault.Client, appRole *v1alpha1.VaultAppRole) (string, error) {
	roleId, secretId, err := v.appRoleRef(appRole)
	if err != nil {
		return "", fmt.Errorf("error reading Vault AppRole from secret: %s/%s: %s", appRole.SecretRef.Name, v.resourceNamespace, err.Error())
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

func (v *Vault) requestVaultCert(commonName string, altNames []string, csr []byte) ([]byte, error) {
	client, err := v.initVaultClient()
	if err != nil {
		return nil, err
	}

	glog.V(4).Infof("Vault certificate request for commonName %s altNames: %q", commonName, altNames)

	parameters := map[string]string{
		"common_name": commonName,
		"alt_names":   strings.Join(altNames, ","),
		"ttl":         defaultCertificateDuration.String(),
		"csr":         string(csr),
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
		return nil, fmt.Errorf("error signing certificate in Vault: %s", err.Error())
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

	secret, err := v.secretsLister.Secrets(v.resourceNamespace).Get(appRole.SecretRef.Name)
	if err != nil {
		return "", "", err
	}

	key := "secretId"
	if appRole.SecretRef.Key != "secretId" {
		key = appRole.SecretRef.Key
	}

	keyBytes, ok := secret.Data[key]
	if !ok {
		return "", "", fmt.Errorf("no data for %q in secret '%s/%s'", key, appRole.SecretRef.Name, v.resourceNamespace)
	}

	secretId = string(keyBytes)
	secretId = strings.TrimSpace(secretId)

	return roleId, secretId, nil
}

func (v *Vault) vaultTokenRef(name, key string) (string, error) {
	secret, err := v.secretsLister.Secrets(v.resourceNamespace).Get(name)
	if err != nil {
		return "", err
	}

	if key == "" {
		key = "token"
	}

	keyBytes, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("no data for %q in secret '%s/%s'", key, name, v.resourceNamespace)
	}

	token := string(keyBytes)
	token = strings.TrimSpace(token)

	return token, nil
}
