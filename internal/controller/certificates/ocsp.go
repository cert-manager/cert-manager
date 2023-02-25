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

package certificates

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ocsp"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/go-logr/logr"
)

const (
	// OCSP Label
	OCSPLabel = "k8s.io/ocsp-staple"

	// The key under which the OCSP staple is stored
	TLSOCSPKey = "tls.ocsp-staple"

	timeoutDuration = 5 * time.Second
	gracePeriod     = 24 * time.Hour

	contentType      = "Content-Type"
	ocspRequestType  = "application/ocsp-request"
	ocspResponseType = "application/ocsp-response"
	ocspStapleLabel  = "kubernetes.io/ocsp-staple"
	accept           = "Accept"
	host             = "host"
)

// This controller is synced on all Certificate 'create', 'update', and
// 'delete' events which will update the metrics for that Certificate.
type OcspManager struct {
	ocspLog logr.Logger
}

// NewSecretsManager returns a new SecretsManager. Setting
// enableSecretOwnerReferences to true will mean that secrets will be deleted
// when the corresponding Certificate is deleted.
func NewOcspManager() *OcspManager {
	return &OcspManager{}
}

func (c *OcspManager) GenerateOcspStaple(ctx context.Context, certBytes []byte) (*ocsp.Response, error) {
	var ocspResponse *ocsp.Response = nil

	cert, err := decodePem(certBytes)
	if err != nil {
		return ocspResponse, err
	}

	timeout, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

	if cert.IssuingCertificateURL == nil {
		return ocspResponse, fmt.Errorf("no issuing certificate URL")
	}

	issuer, err := getIssuerCert(timeout, cert.IssuingCertificateURL[0])
	if err != nil {
		return ocspResponse, err
	}

	c.ocspLog.V(logf.DebugLevel).Info("received the issuer certificate")

	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	buffer, err := ocsp.CreateRequest(cert, issuer, opts)
	if err != nil {
		return ocspResponse, fmt.Errorf("couldn't create OCSP request: %s", err)
	}

	c.ocspLog.V(logf.DebugLevel).Info("created the OCSP request")

	rawOcspStaple, err := c.sendOcspRequest(cert.OCSPServer[0], buffer)
	if err != nil {
		return ocspResponse, fmt.Errorf("failed to send OCSP request: %s", err)
	}

	c.ocspLog.V(logf.DebugLevel).Info("received the OCSP response")

	ocspStaple, err := ocsp.ParseResponse(rawOcspStaple, issuer)
	if err != nil {
		c.ocspLog.V(logf.ErrorLevel).Info("error while parsing the staple: %s", err)
		return nil, nil
	}

	return ocspStaple, nil
}

// sendOcspRequest: send an OCSP request, write the and return the staple
func (c *OcspManager) sendOcspRequest(leafOcsp string, buffer []byte) ([]byte, error) {
	httpRequest, err := http.NewRequest(http.MethodPost, leafOcsp, bytes.NewBuffer(buffer))
	if err != nil {
		return nil, err
	}
	ocspURL, err := url.Parse(leafOcsp)
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Add(contentType, ocspRequestType)
	httpRequest.Header.Add(accept, ocspResponseType)
	httpRequest.Header.Add(host, ocspURL.Host)

	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer httpResponse.Body.Close()
	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}

	return output, nil
}

// check whether the OCSP staple is still valid
func (c *OcspManager) IsOcspStapleValid(rawCertChain []byte, rawStaple []byte) bool {
	ocspStapleValid := false

	cert, err := decodePem(rawCertChain)
	if err != nil {
		c.ocspLog.V(logf.ErrorLevel).Info("Failed to decode PEM: %s", err)
		return ocspStapleValid
	}

	timeout, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	issuer, err := getIssuerCert(timeout, cert.IssuingCertificateURL[0])
	if err != nil {
		c.ocspLog.V(logf.ErrorLevel).Info("Failed to get issuer certificate: %s", err)
		return ocspStapleValid
	}

	staple, err := ocsp.ParseResponse(rawStaple, issuer)
	if err != nil {
		c.ocspLog.V(logf.ErrorLevel).Info("Error while parsing the staple: %s", err)
		return ocspStapleValid
	}

	// grace period of 1 day
	if !staple.NextUpdate.After(time.Now().Add(gracePeriod)) {
		c.ocspLog.V(logf.DebugLevel).Info("Expiry is in %s, which is less than 1 day from now", staple.NextUpdate)
		return ocspStapleValid
	}

	ocspStapleValid = true
	return ocspStapleValid
}

func (c *OcspManager) parseOcspStaple(ctx context.Context, certBytes []byte, rawOcspStaple []byte) (*ocsp.Response, error) {
	var ocspResponse *ocsp.Response = nil

	cert, err := decodePem(certBytes)
	if err != nil {
		return ocspResponse, err
	}

	timeout, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

	issuer, err := getIssuerCert(timeout, cert.IssuingCertificateURL[0])
	if err != nil {
		return ocspResponse, err
	}

	ocspResponse, err = ocsp.ParseResponse(rawOcspStaple, issuer)
	if err != nil {
		c.ocspLog.V(logf.ErrorLevel).Info("error while parsing the staple: %s", err)
		return nil, nil
	}

	return ocspResponse, nil
}

// decodePem: decode the bytes of a certificate chain into a x509 certificate
func decodePem(certInput []byte) (*x509.Certificate, error) {
	var certDERBlock *pem.Block
	certDERBlock, _ = pem.Decode(certInput)

	if certDERBlock == nil {
		return nil, fmt.Errorf("didn't find a PEM block")
	}

	cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	return cert, err
}

// getIssuerCert: given a cert, find its issuer certificate
func getIssuerCert(ctx context.Context, url string) (*x509.Certificate, error) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req = req.WithContext(ctx)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getting cert from %s: %w", url, err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	cert, err := x509.ParseCertificate(body)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	return cert, nil
}
