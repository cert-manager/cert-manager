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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"path"
	"reflect"
	"strings"
	"sync"
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

// clientRepo is a collection of vault clients indexed
// by the options used to create them. This is used so
// that the cert-manager controllers can re-use already
// authenticated vault client
var (
	clientRepo   map[repoKey]*vault.Client
	clientRepoMu sync.Mutex
)

type appRoleAuth struct {
	path, roleId, secretId string
	secretRef              secretRef
}

type secretRef struct {
	key, name string
}

type tokenSecretRef struct {
	key, name, token string
}

type repoKey struct {
	addr        string
	appRoleAuth appRoleAuth
	tokenAuth   tokenSecretRef
}

func (v *Vault) renewToken(vaultClient *vault.Client) {
	resp, err := vaultClient.Auth().Token().LookupSelf()
	if err != nil {
		klog.Warningf("vault: lookup-self failed, token renewal is disabled: %s", err)
		return
	}

	// resp.Data is a *api.Secret type which Unmarshal doesn't take; hence,
	// passing it to Marsha to produce byte arrays to be consumed by Unmarshal
	b, err := json.Marshal(resp.Data)
	var data struct {
		TTL         int       `json:"ttl"`
		CreationTTL int       `json:"creation_ttl"`
		Renewable   bool      `json:"renewable"`
		ExpireTime  time.Time `json:"expire_time"`
	}
	if err := json.Unmarshal(b, &data); err != nil {
		klog.Warningf("vault: lookup-self failed, token renewal is disabled: %s", err)
		return
	}
	if err != nil {
		klog.Warningf("vault: failed to unpack response from LookupSelf(): %s", err)
	}

	switch {
	case data.Renewable:
		// renewable token, proceed further
	case data.ExpireTime.IsZero():
		// nothing to do. token doesn't expire
		return
	default:
		ttl := time.Until(data.ExpireTime) / time.Second * time.Second // truncate to secs
		klog.Warningf("vault: Token is not renewable and it will expire %s from now at %s",
			ttl, data.ExpireTime.Format(time.RFC3339))
		return
	}

	ttl := time.Duration(data.TTL) * time.Second
	timer := time.NewTimer(ttl / 2)

	// make a copy of the current repo key for the given vault
	// client so that it can be used to detect if the vault client changed
	// during token renewal loop
	initialRepoKey, err := v.lookupRepoKey()
	if err != nil {
		vaultClient.ClearToken()
		klog.Warningf("vault client no longer exist or failed to look up vault client")
		return
	}

	for range timer.C {
		curRepoKey, err := v.lookupRepoKey()
		if err != nil {
			vaultClient.ClearToken()
			klog.Warningf("vault client no longer exist or failed to look up vault client", err)
			return
		}

		// current client has updated configs: secret, vault addr and etc
		// if config changes detected, it's time to remove the token so
		// that this client will no longer be used.
		if !reflect.DeepEqual(curRepoKey, initialRepoKey) {
			vaultClient.ClearToken()
			klog.Infof("vault client config changed. Token removed from current client")
			return
		}

		resp, err := vaultClient.Auth().Token().RenewSelf(data.CreationTTL)
		if err != nil {
			vaultClient.ClearToken()
			klog.Warningf("vault: Failed to renew token: %s. Removed it from client", err)
			return
		}

		if !resp.Auth.Renewable || resp.Auth.LeaseDuration == 0 {
			klog.Infof("vault: token is no longer renewable so removed it from client")
			vaultClient.ClearToken()
			return
		}

		// setting new ttl based on the new lease duration
		ttl = time.Duration(resp.Auth.LeaseDuration) * time.Second
		klog.V(4).Infof("Token renewed. New renewal in %s.", ttl/2)
		timer.Reset(ttl / 2)
	}
}

func (v *Vault) lookupRepoKey() (repoKey, error) {
	// Generate vault client repo lookup keys based on vault configurations

	vaultRepo := repoKey{addr: v.issuer.GetSpec().Vault.Server}
	tokenRef := v.issuer.GetSpec().Vault.Auth.TokenSecretRef
	if tokenRef.Name != "" {
		token, err := v.vaultTokenRef(tokenRef.Name, tokenRef.Key)
		vaultRepo.tokenAuth = tokenSecretRef{
			name: tokenRef.Name,
			key:  tokenRef.Key,
		}
		if err != nil {
			return repoKey{}, fmt.Errorf("error reading Vault token from secret %s/%s: %s", v.resourceNamespace, tokenRef.Name, err.Error())
		}
		vaultRepo.tokenAuth.token = token
		return vaultRepo, nil
	}

	appRole := v.issuer.GetSpec().Vault.Auth.AppRole
	if appRole.RoleId != "" {
		roleId, secretId, err := v.appRoleRef(&appRole)
		if err != nil {
			return repoKey{}, fmt.Errorf("error reading Vault AppRole from secret: %s/%s: %s", appRole.SecretRef.Name, v.resourceNamespace, err.Error())
		}
		vaultRepo.appRoleAuth = appRoleAuth{
			roleId:   roleId,
			secretId: secretId,
		}

		vaultRepo.appRoleAuth.path = "approle"
		if appRole.Path != "approle" {
			vaultRepo.appRoleAuth.path = appRole.Path
		}

		vaultRepo.appRoleAuth.secretRef = secretRef{key: "secretId"}
		if appRole.SecretRef.Key != "secretId" {
			vaultRepo.appRoleAuth.secretRef.key = appRole.SecretRef.Key
		}

		vaultRepo.appRoleAuth.secretRef.name = appRole.SecretRef.Name
		return vaultRepo, nil
	}
	return vaultRepo, fmt.Errorf("error initializing Vault client. tokenSecretRef or appRoleSecretRef not set")
}

func (v *Vault) initVaultClient() (*vault.Client, error) {
	clientRepoMu.Lock()
	defer clientRepoMu.Unlock()

	if clientRepo == nil {
		clientRepo = make(map[repoKey]*vault.Client)
	}

	vaultRepoKey, err := v.lookupRepoKey()
	if err != nil {
		klog.Warningf("failed to gen keys for clientRepo: %s", err.Error())
	}

	if clientRepo[vaultRepoKey] != nil {
		if len(clientRepo[vaultRepoKey].Token()) > 0 {
			klog.V(4).Info("Using cached client")
			return clientRepo[vaultRepoKey], nil
		}
		delete(clientRepo, vaultRepoKey)
		klog.V(4).Infof("Token is gone for cached client so removed it from clientRepo")
	}

	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = v.issuer.GetSpec().Vault.Server
	err = v.configureCertPool(vaultCfg)
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
		if vaultRepoKey != (repoKey{}) {
			// only store authenticated client if repoKey is not empty
			// because otherwise we don't know how to look up the client
			// in successive runs
			clientRepo[vaultRepoKey] = client
			go v.renewToken(client)
			return client, nil
		}
	}

	appRole := v.issuer.GetSpec().Vault.Auth.AppRole
	if appRole.RoleId != "" {
		token, err := v.requestTokenWithAppRoleRef(client, &appRole)
		if err != nil {
			return nil, fmt.Errorf("error reading Vault token from AppRole: %s", err.Error())
		}
		client.SetToken(token)
		if vaultRepoKey != (repoKey{}) {
			clientRepo[vaultRepoKey] = client
			go v.renewToken(client)
			return client, nil
		}
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
