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

package secret

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/ocsp"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func fingerprintCert(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	fingerprint := sha256.Sum256(cert.Raw)

	var buf bytes.Buffer
	for i, f := range fingerprint {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}

	return buf.String()
}

func checkOCSPValidCert(leafCert, issuerCert *x509.Certificate) (bool, error) {
	if len(leafCert.OCSPServer) < 1 {
		return false, errors.New("No OCSP Server set")
	}
	buffer, err := ocsp.CreateRequest(leafCert, issuerCert, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return false, fmt.Errorf("error creating OCSP request: %w", err)
	}

	for _, ocspServer := range leafCert.OCSPServer {
		httpRequest, err := http.NewRequest(http.MethodPost, ocspServer, bytes.NewBuffer(buffer))
		if err != nil {
			return false, fmt.Errorf("error creating HTTP request: %w", err)
		}
		ocspUrl, err := url.Parse(ocspServer)
		if err != nil {
			return false, fmt.Errorf("error parsing OCSP URL: %w", err)
		}
		httpRequest.Header.Add("Content-Type", "application/ocsp-request")
		httpRequest.Header.Add("Accept", "application/ocsp-response")
		httpRequest.Header.Add("Host", ocspUrl.Host)
		httpClient := &http.Client{}
		httpResponse, err := httpClient.Do(httpRequest)
		if err != nil {
			return false, fmt.Errorf("error making HTTP request: %w", err)
		}
		defer httpResponse.Body.Close()
		output, err := io.ReadAll(httpResponse.Body)
		if err != nil {
			return false, fmt.Errorf("error reading HTTP body: %w", err)
		}
		ocspResponse, err := ocsp.ParseResponse(output, issuerCert)
		if err != nil {
			return false, fmt.Errorf("error reading OCSP response: %w", err)
		}

		if ocspResponse.Status == ocsp.Revoked {
			// one OCSP revoked it do not trust
			return false, nil
		}
	}

	return true, nil
}

func checkCRLValidCert(cert *x509.Certificate, url string) (bool, error) {
	resp, err := http.Get(url)
	if err != nil {
		return false, fmt.Errorf("error getting HTTP response: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("error reading HTTP body: %w", err)
	}
	resp.Body.Close()

	crl, err := x509.ParseCRL(body)
	if err != nil {
		return false, fmt.Errorf("error parsing HTTP body: %w", err)
	}

	// TODO: check CRL signature

	for _, revoked := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			return false, nil
		}
	}

	return true, nil
}

func printSlice(in []string) string {
	if len(in) < 1 {
		return "<none>"
	}

	return "\n\t\t- " + strings.Trim(strings.Join(in, "\n\t\t- "), " ")
}

func printSliceOrOne(in []string) string {
	if len(in) < 1 {
		return "<none>"
	} else if len(in) == 1 {
		return in[0]
	}

	return printSlice(in)
}

func printOrNone(in string) string {
	if in == "" {
		return "<none>"
	}

	return in
}

func printKeyUsage(in []cmapi.KeyUsage) string {
	if len(in) < 1 {
		return " <none>"
	}

	var usageStrings []string
	for _, usage := range in {
		usageStrings = append(usageStrings, string(usage))
	}

	return "\n\t\t- " + strings.Trim(strings.Join(usageStrings, "\n\t\t- "), " ")
}

func splitPEMs(certData []byte) ([][]byte, error) {
	certs := [][]byte(nil)
	for {
		block, rest := pem.Decode(certData)
		if block == nil {
			break // got no more certs to decode
		}
		// ignore private key data
		if block.Type == "CERTIFICATE" {
			buf := bytes.NewBuffer(nil)
			err := pem.Encode(buf, block)
			if err != nil {
				return nil, fmt.Errorf("error when reencoding PEM: %s", err)
			}
			certs = append(certs, buf.Bytes())
		}
		certData = rest
	}
	return certs, nil
}
