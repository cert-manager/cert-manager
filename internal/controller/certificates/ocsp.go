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

	"github.com/go-logr/logr"
	"golang.org/x/crypto/ocsp"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

const (
	// OCSP Label
	OCSPLabel = "k8s.io/ocsp-staple"

	timeoutDuration = 5 * time.Second
	gracePeriodDays = 1
	gracePeriod     = gracePeriodDays * 24 * time.Hour

	contentType      = "Content-Type"
	ocspRequestType  = "application/ocsp-request"
	ocspResponseType = "application/ocsp-response"
	ocspStapleLabel  = "kubernetes.io/ocsp-staple"
	accept           = "Accept"
	host             = "host"
)

type OcspManager struct {
	ocspLog logr.Logger
}

var (
	ocspParser = ocsp.ParseResponse
)

func NewOcspManager() *OcspManager {
	return &OcspManager{}
}

func (c *OcspManager) GetOCSPResponse(ctx context.Context, crt *cmapi.Certificate, req *cmapi.CertificateRequest) (*ocsp.Response, error) {
	var emptyResponse *ocsp.Response = nil
	crt = crt.DeepCopy()

	certBytes := req.Status.Certificate
	cert, err := decodePem(certBytes)
	if err != nil {
		return emptyResponse, err
	}
	if cert.IssuingCertificateURL == nil {
		return emptyResponse, fmt.Errorf("no issuing certificate URL")
	}

	timeout, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()
	issuer, err := getIssuerCert(timeout, cert.IssuingCertificateURL[0])
	if err != nil {
		return emptyResponse, err
	}
	c.ocspLog.V(logf.DebugLevel).Info("received the issuer certificate")
	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	buffer, err := ocsp.CreateRequest(cert, issuer, opts)
	if err != nil {
		return emptyResponse, fmt.Errorf("couldn't create OCSP request: %s", err)
	}
	c.ocspLog.V(logf.DebugLevel).Info("created the OCSP request")

	rawOcspStaple, err := c.sendOcspRequest(cert.OCSPServer[0], buffer)

	if err != nil {
		return emptyResponse, fmt.Errorf("failed to send OCSP request: %s", err)
	}

	c.ocspLog.V(logf.DebugLevel).Info("received the OCSP response")
	ocspStaple, err := ocspParser(rawOcspStaple, issuer)

	if err != nil {
		c.ocspLog.V(logf.ErrorLevel).Info("error while parsing the staple: %s", err)
		return emptyResponse, nil
	}

	return ocspStaple, nil
}

func (c *OcspManager) IsOcspStapleValid(rawCertChain []byte, rawStaple []byte) bool {
	cert, err := decodePem(rawCertChain)
	if err != nil {
		c.ocspLog.V(logf.ErrorLevel).Info("Failed to decode PEM: %s", err)
		return false
	}

	timeout, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	issuer, err := getIssuerCert(timeout, cert.IssuingCertificateURL[0])
	if err != nil {
		c.ocspLog.V(logf.ErrorLevel).Info("Failed to get issuer certificate: %s", err)
		return false
	}

	staple, err := ocspParser(rawStaple, issuer)
	if err != nil {
		c.ocspLog.V(logf.ErrorLevel).Info("Error while parsing the staple: %s", err)
		return false
	}

	if time.Now().After(staple.NextUpdate.Add(-gracePeriod)) {
		c.ocspLog.V(logf.DebugLevel).Info("Expiry for OCSP Staple is in %s, which is less than %d day/s from now", staple.NextUpdate, gracePeriodDays)
		return false
	}

	return true
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

// sendOcspRequest: send an OCSP request, write and return the staple
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
