package cfssl

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
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
	// get existing certificate private key
	signeeKey, err := kube.SecretPrivateKey(c.secretsLister, crt.Namespace, crt.Spec.SecretName)
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		keySpec := crt.Spec.CFSSL.Key
		signeeKey, err = pki.GeneratePrivateKey(keySpec.Algo, keySpec.Size)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating private key: %s", err)
		}
	}

	certPem, err := c.signCertificate(ctx, crt, signeeKey)
	if err != nil {
		return nil, nil, err
	}

	signeeKeyPem, err := pki.EncodePrivateKey(signeeKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error encoding private key: %s", err)
	}

	return signeeKeyPem, certPem, nil
}

func (c *CFSSL) signCertificate(ctx context.Context, crt *v1alpha1.Certificate, key crypto.PrivateKey) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: pki.CommonNameForCertificate(crt),
		},
		DNSNames: pki.DNSNamesForCertificate(crt),
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("error creating certificate request: %s", err)
	}

	block := pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}
	csrPem := pem.EncodeToMemory(&block)

	requestBody, err := c.buildRequestBody(csrPem)
	if err != nil {
		return nil, fmt.Errorf("error building request body: %s", err)
	}

	issuerSpec := c.issuer.GetSpec().CFSSL
	url := fmt.Sprintf("%s%s", issuerSpec.Server, issuerSpec.Path)

	requestCtx, cancel := context.WithTimeout(ctx, defaultRequestTimeoutSec*time.Second)
	defer cancel()

	httpRequest, err := http.NewRequest("POST", url, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("error building http post request: %s", err)
	}

	httpRequest = httpRequest.WithContext(requestCtx)
	httpResponse, err := http.DefaultClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("error making request to remote cfssl server: %s", err)
	}

	if httpResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(messageRemoteServerResponseNon2xx)
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

func (c *CFSSL) buildRequestBody(csrPem []byte) ([]byte, error) {
	request := Request{CertificateRequest: string(csrPem)}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	authKeySecret := c.issuer.GetSpec().CFSSL.AuthKey
	if authKeySecret == nil {
		return requestBytes, nil
	}

	secret, err := c.secretsLister.Secrets(c.issuerResourcesNamespace).Get(authKeySecret.Name)
	if err != nil {
		return nil, err
	}

	keyBytes, ok := secret.Data[authKeySecret.Key]
	if !ok {
		return nil, fmt.Errorf("no data for %q in secret '%s/%s'", authKeySecret.Key, authKeySecret.Name, c.issuerResourcesNamespace)
	}

	authKey := strings.TrimSpace(string(keyBytes))
	hexAuthKey, err := hex.DecodeString(authKey)
	if err != nil {
		return nil, fmt.Errorf("%s %s", messageAuthKeyFormat, err)
	}

	h := hmac.New(sha256.New, []byte(hexAuthKey))
	h.Write(requestBytes)

	authenticatedRequest := AuthenticatedRequest{
		Token:   base64.StdEncoding.EncodeToString(h.Sum(nil)),
		Request: base64.StdEncoding.EncodeToString(requestBytes),
	}

	return json.Marshal(authenticatedRequest)
}
