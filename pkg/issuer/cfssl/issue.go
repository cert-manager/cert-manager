package cfssl

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	errorIssueCert = "ErrIssueCert"

	successCertIssued = "CertIssueSuccess"

	messageCertIssued                     = "Certificate issued successfully"
	messageErrorIssueCert                 = "Error issuing TLS certificate: "
	messageAuthKeyFormat                  = "authkey must be in hexadecimal format: "
	messageHMACWrite                      = "failed to write data to hash: "
	messageRemoteServerResponseNotSuccess = "remote cfssl server failed to sign certificate request"
	messageRemoteServerResponseNon2xx     = "server returned a non 2xx response"
)

const defaultRequestTimeoutSec = 5

func (c *CFSSL) Issue(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	keyPem, certPem, err := c.obtainCertificate(ctx, crt)

	if err != nil {
		s := messageErrorIssueCert + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueCert, s, false)
		return nil, nil, err
	}

	crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, successCertIssued, messageCertIssued, true)

	return keyPem, certPem, nil
}

func (c *CFSSL) obtainCertificate(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	signeeKey, err := kube.SecretTLSKey(c.secretsLister, crt.Namespace, crt.Spec.SecretName)

	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		signeeKey, err = pki.GeneratePrivateKeyForCertificate(crt)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating private key: %s", err)
		}
	}

	certPem, err := c.signCertificate(ctx, crt, signeeKey)
	if err != nil {
		return nil, nil, err
	}

	keyPem, err := pki.EncodePrivateKey(signeeKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error encoding private key: %s", err)
	}

	return keyPem, certPem, nil
}

func (c *CFSSL) signCertificate(ctx context.Context, crt *v1alpha1.Certificate, key crypto.PrivateKey) ([]byte, error) {
	template, err := pki.GenerateCSR(c.issuer, crt)
	if err != nil {
		return nil, fmt.Errorf("error generating CSR template: %s", err)
	}

	request, err := c.buildRequest(crt, template, key)
	if err != nil {
		return nil, fmt.Errorf("error building request body: %s", err)
	}

	certificate, err := c.sendRequest(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("error requesting certificate from server: %s", err)
	}

	return certificate, nil
}

func (c *CFSSL) buildRequest(crt *v1alpha1.Certificate, template *x509.CertificateRequest, key crypto.PrivateKey) (Request, error) {
	spec := c.issuer.GetSpec().CFSSL
	if spec == nil {
		return nil, fmt.Errorf("unexpected error: cfssl issuer spec should not be nil")
	}

	authKeySecretSelector := spec.AuthKey
	if authKeySecretSelector == nil {
		// If authkey is not provided for the issuer, it means the request should
		// be sent to the issuer as is without hmac encoding.
		return c.buildUnauthenticatedRequest(crt, template, key)
	}

	return c.buildAuthenticatedRequest(crt, template, key, authKeySecretSelector)
}

func (c *CFSSL) sendRequest(ctx context.Context, request Request) ([]byte, error) {
	spec := c.issuer.GetSpec().CFSSL
	if spec == nil {
		return nil, fmt.Errorf("unexpected error: issuer spec should not be nil")
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("error marshalling request: %s", err)
	}

	requestCtx, cancel := context.WithTimeout(ctx, defaultRequestTimeoutSec*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s%s", spec.Server, spec.Path)
	httpRequest, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("error building http post request: %s", err)
	}

	httpRequest = httpRequest.WithContext(requestCtx)
	httpResponse, err := http.DefaultClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("error making request to remote cfssl server: %s", err)
	}

	if httpResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %d", messageRemoteServerResponseNon2xx, httpResponse.StatusCode)
	}

	var response Response
	err = json.NewDecoder(httpResponse.Body).Decode(&response)
	if err != nil {
		return nil, fmt.Errorf("error decoding cfssl server response: %s", err)
	}

	if !response.Success {
		return nil, fmt.Errorf(messageRemoteServerResponseNotSuccess)
	}

	certificate, ok := response.Result["certificate"]
	if !ok {
		return nil, fmt.Errorf("unexpected response received from cfssl server")
	}

	return []byte(certificate.(string)), nil
}

func (c *CFSSL) buildUnauthenticatedRequest(crt *v1alpha1.Certificate, template *x509.CertificateRequest, key crypto.PrivateKey) (*UnauthenticatedRequest, error) {
	csrBytes, err := pki.EncodeCSR(template, key)
	if err != nil {
		return nil, err
	}

	block := pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}
	csrPem := pem.EncodeToMemory(&block)

	request := &UnauthenticatedRequest{CertificateRequest: string(csrPem)}

	spec := crt.Spec.CFSSL
	if spec != nil {
		if len(spec.Profile) > 0 {
			request.Profile = spec.Profile
		}
		if len(spec.Label) > 0 {
			request.Label = spec.Label
		}
	}

	return request, nil
}

func (c *CFSSL) buildAuthenticatedRequest(crt *v1alpha1.Certificate,
	template *x509.CertificateRequest,
	key crypto.PrivateKey,
	secretSelector *v1alpha1.SecretKeySelector) (*AuthenticatedRequest, error) {

	secret, err := c.secretsLister.Secrets(c.issuerResourcesNamespace).Get(secretSelector.Name)
	if err != nil {
		return nil, err
	}

	keyBytes, ok := secret.Data[secretSelector.Key]
	if !ok {
		return nil, fmt.Errorf("no data for %q in secret '%s/%s'", secretSelector.Key, secretSelector.Name, c.issuerResourcesNamespace)
	}

	request, err := c.buildUnauthenticatedRequest(crt, template, key)
	if err != nil {
		return nil, err
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	authKey := strings.TrimSpace(string(keyBytes))
	hexAuthKey, err := hex.DecodeString(authKey)
	if err != nil {
		return nil, fmt.Errorf("%s %s", messageAuthKeyFormat, err)
	}

	h := hmac.New(sha256.New, []byte(hexAuthKey))
	_, err = h.Write(requestBytes)
	if err != nil {
		return nil, fmt.Errorf("%s %s", messageHMACWrite, err)
	}

	return &AuthenticatedRequest{
		Token:   base64.StdEncoding.EncodeToString(h.Sum(nil)),
		Request: base64.StdEncoding.EncodeToString(requestBytes),
	}, nil
}
