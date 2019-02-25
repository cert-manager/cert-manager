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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/certutil"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	errorGetCertKeyPair = "ErrGetCertKeyPair"
	errorIssueCert      = "ErrIssueCert"

	successCertIssued = "CertIssueSuccess"

	messageErrorIssueCert = "Error issuing TLS certificate: "

	messageCertIssued = "Certificate issued successfully"
)

func (v *Vault) Issue(ctx context.Context, crt *v1alpha1.Certificate) (*issuer.IssueResponse, error) {
	// get a copy of the existing/currently issued Certificate's private key
	signeePrivateKey, err := kube.SecretTLSKey(v.secretsLister, crt.Namespace, crt.Spec.SecretName)
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		// if one does not already exist, generate a new one
		signeePrivateKey, err = pki.GeneratePrivateKeyForCertificate(crt)
		if err != nil {
			v.Recorder.Eventf(crt, corev1.EventTypeWarning, "PrivateKeyError", "Error generating certificate private key: %v", err)
			// don't trigger a retry. An error from this function implies some
			// invalid input parameters, and retrying without updating the
			// resource will not help.
			return nil, nil
		}
	}
	if err != nil {
		klog.Errorf("Error getting private key %q for certificate: %v", crt.Spec.SecretName, err)
		return nil, err
	}

	/// BEGIN building CSR
	// TODO: we should probably surface some of these errors to users
	template, err := pki.GenerateCSR(v.issuer, crt)
	if err != nil {
		return nil, err
	}
	derBytes, err := pki.EncodeCSR(template, signeePrivateKey)
	if err != nil {
		return nil, err
	}
	pemRequestBuf := &bytes.Buffer{}
	err = pem.Encode(pemRequestBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: derBytes})
	if err != nil {
		return nil, fmt.Errorf("error encoding certificate request: %s", err.Error())
	}
	/// END building CSR

	/// BEGIN requesting certificate
	certDuration := v1alpha1.DefaultCertificateDuration
	if crt.Spec.Duration != nil {
		certDuration = crt.Spec.Duration.Duration
	}

	certPem, caPem, err := v.requestVaultCert(template.Subject.CommonName, certDuration, template.DNSNames, pki.IPAddressesToString(template.IPAddresses), pemRequestBuf.Bytes())
	if err != nil {
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Failed to request certificate: %v", err)
		return nil, err
	}
	/// END requesting certificate

	key, err := pki.EncodePrivateKey(signeePrivateKey)
	if err != nil {
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorPrivateKey", "Error encoding private key: %v", err)
		return nil, err
	}

	return &issuer.IssueResponse{
		PrivateKey:  key,
		Certificate: certPem,
		CA:          caPem,
	}, nil
}

func (v *Vault) configureCertPool(cfg *vault.Config) error {
	certs := v.issuer.GetSpec().Vault.CABundle
	if len(certs) == 0 {
		return nil
	}

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(certs)
	if ok == false {
		return fmt.Errorf("error loading Vault CA bundle")
	}

	cfg.HttpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = caCertPool

	return nil
}

func (v *Vault) initVaultClient() (*vault.Client, error) {
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = v.issuer.GetSpec().Vault.Server
	err := v.configureCertPool(vaultCfg)
	if err != nil {
		return nil, err
	}

	client, err := vault.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("error initializing Vault client: %s", err.Error())
	}

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

func (v *Vault) requestVaultCert(commonName string, certDuration time.Duration, altNames []string, ipSans []string, csr []byte) ([]byte, []byte, error) {

	client, err := v.initVaultClient()
	if err != nil {
		return nil, nil, err
	}

	klog.V(4).Infof("Vault certificate request for commonName %s altNames: %q ipSans: %q", commonName, altNames, ipSans)

	parameters := map[string]string{
		"common_name":          commonName,
		"alt_names":            strings.Join(altNames, ","),
		"ip_sans":              strings.Join(ipSans, ","),
		"ttl":                  certDuration.String(),
		"csr":                  string(csr),
		"exclude_cn_from_sans": "true",
	}

	url := path.Join("/v1", v.issuer.GetSpec().Vault.Path)

	request := client.NewRequest("POST", url)

	err = request.SetJSONBody(parameters)
	if err != nil {
		return nil, nil, fmt.Errorf("error encoding Vault parameters: %s", err.Error())
	}

	resp, err := client.RawRequest(request)
	if err != nil {
		return nil, nil, fmt.Errorf("error signing certificate in Vault: %s", err.Error())
	}

	defer resp.Body.Close()

	vaultResult := certutil.Secret{}
	resp.DecodeJSON(&vaultResult)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to decode JSON payload: %s", err.Error())
	}

	parsedBundle, err := certutil.ParsePKIMap(vaultResult.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse certificate: %s", err.Error())
	}

	bundle, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to convert certificate bundle to PEM bundle: %s", err.Error())
	}

	var caPem []byte = nil
	if len(bundle.CAChain) > 0 {
		caPem = []byte(bundle.CAChain[0])
	}

	return []byte(bundle.ToPEMBundle()), caPem, nil
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
