/*
Copyright 2018 The Jetstack cert-manager contributors.

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

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	infoEndpoint     = "/info"
	signEndpoint     = "/sign"
	authSignEndpoint = "/authsign"

	// Client timeout when communicating with remote CFSSL server
	defaultRequestTimeoutSec = 5
)

const (
	reasonErrorPrivateKey = "ErrorPrivateKey"
	reasonErrorCA         = "ErrorCA"
	reasonErrorIssuerSpec = "ErrorIssuerSpec"
	reasonErrorSigning    = "ErrorSigning"
	reasonErrorCSR        = "ErrorCSR"
	reasonErrorCARequest  = "ErrorCARequest"

	messageAuthKeyFormat            = "Error decoding auth key as hexadecimal: "
	messageServerResponseNotSuccess = "server response not successful"
	messageServerResponseNon2xx     = "server returned a non 2xx response"
)

func (c *CFSSL) Issue(ctx context.Context, crt *v1alpha1.Certificate) (*issuer.IssueResponse, error) {
	// get a copy of the existing/currently issued Certificate's private key
	signeeKey, err := kube.SecretTLSKey(c.secretsLister, crt.Namespace, crt.Spec.SecretName)
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		// if one does not already exist, generate a new one
		signeeKey, err = pki.GeneratePrivateKeyForCertificate(crt)
		if err != nil {
			c.Recorder.Eventf(crt, corev1.EventTypeWarning, reasonErrorPrivateKey, "Error generating certificate private key: %v", err)
			// don't trigger a retry. An error from this function implies some
			// invalid input parameters, and retrying without updating the
			// resource will not help.
			return nil, nil
		}
	}

	if err != nil {
		glog.Errorf("Error getting private key %q for certificate: %v", crt.Spec.SecretName, err)
		return nil, err
	}

	// check if issuer config is set as we cannot proceed without it
	issuerSpec := c.issuer.GetSpec().CFSSL
	if issuerSpec == nil {
		c.Recorder.Event(crt, corev1.EventTypeWarning, reasonErrorIssuerSpec, "CFSSL issuer spec should not be nil")
		return nil, fmt.Errorf("UnexpectedError: CFSSL issuer spec should not be nil")
	}

	// generate a x509 certificate request template for this Certificate
	template, err := pki.GenerateCSR(c.issuer, crt)
	if err != nil {
		c.Recorder.Eventf(crt, corev1.EventTypeWarning, reasonErrorCSR, "Error generating certificate request: %v", err)
		return nil, err
	}

	// Fetch CA cert from remote CFSSL server
	caCertRequest := InfoRequest{}
	caCertResponse, err := doRequest(caCertRequest, apiPath(issuerSpec.Server, issuerSpec.APIPrefix, infoEndpoint))
	if err != nil {
		c.Recorder.Eventf(crt, corev1.EventTypeWarning, reasonErrorCA, "Error getting CA certificate from remote server: %v", err)
		return nil, err
	}

	var certRequest Request
	var serverAddress string
	if issuerSpec.AuthKey == nil {
		// If authkey is not provided for the issuer, it means the request should
		// be sent to the issuer as is without hmac encoding.
		certRequest, err = buildUnauthenticatedSignRequest(crt, template, signeeKey)
		if err != nil {
			c.Recorder.Eventf(crt, corev1.EventTypeWarning, reasonErrorCARequest, "Error building CFSSL request payload: %v", err)
			return nil, err
		}
		serverAddress = apiPath(issuerSpec.Server, issuerSpec.APIPrefix, signEndpoint)
	} else {
		secret, err := c.secretsLister.Secrets(c.resourceNamespace).Get(issuerSpec.AuthKey.Name)
		if err != nil {
			c.Recorder.Eventf(crt, corev1.EventTypeWarning, reasonErrorIssuerSpec, "Error getting issuer auth key secret: %v", err)
			return nil, err
		}

		keyBytes, ok := secret.Data[issuerSpec.AuthKey.Key]
		if !ok {
			kErr := fmt.Errorf("no data for %q in secret '%s/%s'", issuerSpec.AuthKey.Key, issuerSpec.AuthKey.Name, c.resourceNamespace)
			c.Recorder.Eventf(crt, corev1.EventTypeWarning, reasonErrorIssuerSpec, "Error getting issuer auth key from secret: %v", kErr)
			return nil, kErr
		}

		serverAuthKey, err := hex.DecodeString(strings.TrimSpace(string(keyBytes)))
		if err != nil {
			c.Recorder.Eventf(crt, corev1.EventTypeWarning, reasonErrorIssuerSpec, "Error decoding auth key as hexadecimal: %v", err)
			return nil, fmt.Errorf("Error decoding auth key as hexadecimal: %v", err)
		}

		certRequest, err = buildAuthenticatedSignRequest(crt, template, signeeKey, serverAuthKey)
		if err != nil {
			c.Recorder.Eventf(crt, corev1.EventTypeWarning, reasonErrorCARequest, "Error building CFSSL request payload: %v", err)
			return nil, err
		}
		serverAddress = apiPath(issuerSpec.Server, issuerSpec.APIPrefix, authSignEndpoint)
	}

	certResponse, err := doRequest(certRequest, serverAddress)
	if err != nil {
		c.Recorder.Eventf(crt, corev1.EventTypeWarning, reasonErrorSigning, "Error requesting certificate from remote server: %v", err)
		return nil, err
	}

	// Encode output private key and CA cert ready for return
	keyPem, err := pki.EncodePrivateKey(signeeKey)
	if err != nil {
		c.Recorder.Eventf(crt, corev1.EventTypeWarning, reasonErrorPrivateKey, "Error encoding private key: %v", err)
	}

	return &issuer.IssueResponse{
		PrivateKey:  keyPem,
		Certificate: []byte(certResponse.Result.Certificate),
		CA:          []byte(caCertResponse.Result.Certificate),
	}, nil
}

func buildUnauthenticatedSignRequest(crt *v1alpha1.Certificate, template *x509.CertificateRequest, key crypto.Signer) (*UnauthenticatedSignRequest, error) {
	csrBytes, err := pki.EncodeCSR(template, key)
	if err != nil {
		return nil, err
	}

	block := pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}
	csrPem := pem.EncodeToMemory(&block)

	request := &UnauthenticatedSignRequest{CertificateRequest: string(csrPem)}

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

func buildAuthenticatedSignRequest(crt *v1alpha1.Certificate, template *x509.CertificateRequest, key crypto.Signer, serverAuthKey []byte) (*AuthenticatedSignRequest, error) {
	request, err := buildUnauthenticatedSignRequest(crt, template, key)
	if err != nil {
		return nil, err
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	h := hmac.New(sha256.New, serverAuthKey)
	_, err = h.Write(requestBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to write data to hash: %v", err)
	}

	return &AuthenticatedSignRequest{
		Token:   base64.StdEncoding.EncodeToString(h.Sum(nil)),
		Request: base64.StdEncoding.EncodeToString(requestBytes),
	}, nil
}

func doRequest(payload Request, address string) (*Response, error) {
	client := &http.Client{
		Timeout: defaultRequestTimeoutSec * time.Second,
	}

	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(payload)
	if err != nil {
		return nil, fmt.Errorf("error marshalling request payload: %s", err)
	}

	httpRequest, err := http.NewRequest("POST", address, body)
	if err != nil {
		return nil, fmt.Errorf("error building http post request: %s", err)
	}

	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("error making request to remote cfssl server: %s", err)
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %d", messageServerResponseNon2xx, httpResponse.StatusCode)
	}

	var response Response
	err = json.NewDecoder(httpResponse.Body).Decode(&response)
	if err != nil {
		return nil, fmt.Errorf("error decoding cfssl server response: %s", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("%s: %v", messageServerResponseNotSuccess, response.Errors)
	}

	return &response, nil
}

func apiPath(address, apiPrefix, path string) string {
	// Check if address ends with '/', eg http.my.server/
	if strings.HasSuffix(address, "/") {
		address = address[:len(address)-1]
	}

	// Check if apiPrefix ends with '/', eg /v1/certificates/
	if strings.HasSuffix(apiPrefix, "/") {
		apiPrefix = apiPrefix[:len(apiPrefix)-1]
	}

	// Check if apiPrefix does not start with '/', e.g v1/certificates
	if !strings.HasPrefix(apiPrefix, "/") {
		apiPrefix = "/" + apiPrefix
	}

	return fmt.Sprintf("%s%s%s", address, apiPrefix, path)
}
