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

package venafi

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/Venafi/vcert/pkg/venafi/fake"

	internalvanafiapi "github.com/jetstack/cert-manager/pkg/internal/venafi/api"
	internalfake "github.com/jetstack/cert-manager/pkg/internal/venafi/fake"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

func checkCertificateIssued(t *testing.T, csrPEM []byte, resp []byte) {
	if len(resp) == 0 {
		t.Errorf("expected IssueResponse to be non-nil")
		t.FailNow()
		return
	}

	csr, err := pki.DecodeX509CertificateRequestBytes(csrPEM)
	if err != nil {
		t.Errorf("failed to decode CSR PEM: %s", err)
		return
	}

	crt, err := pki.DecodeX509CertificateBytes(resp)
	if err != nil {
		t.Errorf("unable to decode x509 certificate: %v", err)
		return
	}

	ok, err := pki.PublicKeyMatchesCSR(crt.PublicKey, csr)
	if err != nil {
		t.Errorf("error checking private key: %v", err)
		return
	}
	if !ok {
		t.Errorf("private key does not match certificate")
	}

	// validate the common name is correct
	expectedCN := csr.Subject.CommonName
	if expectedCN != crt.Subject.CommonName {
		t.Errorf("expected common name to be %q but it was %q", expectedCN, crt.Subject.CommonName)
	}

	// validate the dns names are correct
	expectedDNSNames := csr.DNSNames
	if !util.EqualUnsorted(crt.DNSNames, expectedDNSNames) {
		t.Errorf("expected dns names to be %q but it was %q", expectedDNSNames, crt.DNSNames)
	}
}

func checkNoCertificateIssued(t *testing.T, csrPEM []byte, resp []byte) {
	if len(resp) > 0 {
		t.Errorf("expected no response with error but got=%s", resp)
	}
}

func generateCSR(t *testing.T, sk crypto.Signer, commonName string, dnsNames []string) []byte {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           dnsNames,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, sk)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return csr
}

func TestSign(t *testing.T) {
	sk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	csrPEM := generateCSR(t, sk, "common-name", []string{
		"foo.example.com", "bar.example.com"})

	csrNonePEM := generateCSR(t, sk, "", []string{})

	tests := map[string]testSignT{
		"if reading the zone configuration fails then error": {
			csrPEM:      csrPEM,
			checkFn:     checkNoCertificateIssued,
			expectedErr: true,
			client: internalfake.Connector{
				ReadZoneConfigurationFunc: func() (*endpoint.ZoneConfiguration, error) {
					return nil, errors.New("zone configuration error")
				},
			}.Default(),
		},
		"if validating the certificate fails then error": {
			csrPEM:      csrPEM,
			checkFn:     checkNoCertificateIssued,
			expectedErr: true,
			client: internalfake.Connector{
				ReadZoneConfigurationFunc: func() (*endpoint.ZoneConfiguration, error) {
					return &endpoint.ZoneConfiguration{
						Policy: endpoint.Policy{
							SubjectCNRegexes: []string{"foo"},
						},
					}, nil
				},
			}.Default(),
		},
		"a badly formed CSR should error": {
			csrPEM:      []byte("a badly formed CSR"),
			checkFn:     checkNoCertificateIssued,
			expectedErr: true,
		},
		"if requesting the certificate fails, sign should error": {
			csrPEM: csrPEM,
			client: internalfake.Connector{
				RequestCertificateFunc: func(*certificate.Request) (string, error) {
					return "", errors.New("request error")
				},
			}.Default(),
			checkFn:     checkNoCertificateIssued,
			expectedErr: true,
		},
		"if retrieve certificate fails, sign should error": {
			csrPEM: csrPEM,
			client: internalfake.Connector{
				RetrieveCertificateFunc: func(*certificate.Request) (*certificate.PEMCollection, error) {
					return nil, errors.New("request error")
				},
			}.Default(),
			checkFn:     checkNoCertificateIssued,
			expectedErr: true,
		},
		"if no Common Name, DNS Name, or URI SANs in CSR then error": {
			csrPEM:      csrNonePEM,
			checkFn:     checkNoCertificateIssued,
			expectedErr: true,
		},
		"obtain a certificate with DNS names specified": {
			csrPEM:      csrPEM,
			checkFn:     checkCertificateIssued,
			expectedErr: false,
		},
		"obtain a certificate with custom fields specified": {
			csrPEM:       csrPEM,
			customFields: []internalvanafiapi.CustomField{{Name: "test", Value: "ok"}},
			client: internalfake.Connector{
				RetrieveCertificateFunc: func(r *certificate.Request) (*certificate.PEMCollection, error) {
					// we set 1 field by default
					if len(r.CustomFields) <= 1 {
						return nil, errors.New("custom fields not set")
					}
					foundFields := false
					for _, fieldSet := range r.CustomFields {
						if fieldSet.Name != "test" && fieldSet.Value != "ok" {
							foundFields = true
						}
					}
					if !foundFields {
						return nil, errors.New("custom fields content not correct")
					}
					return internalfake.Connector{}.Default().RetrieveCertificate(r) // hack to return to normal
				},
			}.Default(),
			checkFn:     checkCertificateIssued,
			expectedErr: false,
		},
		"If invalid custom field type found the error": {
			csrPEM:       csrPEM,
			customFields: []internalvanafiapi.CustomField{{Name: "test", Value: "ok", Type: "Bool"}},
			checkFn:      checkNoCertificateIssued,
			expectedErr:  true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.runTest(t)
		})
	}
}

type testSignT struct {
	csrPEM []byte
	client connector

	expectedErr bool

	customFields []internalvanafiapi.CustomField

	checkFn func(*testing.T, []byte, []byte)
}

func (s *testSignT) runTest(t *testing.T) {
	client := s.client
	if client == nil {
		client = fake.NewConnector(true, nil)
	}

	v := &Venafi{
		client: client,
	}

	resp, _, err := v.Sign(s.csrPEM, time.Minute, s.customFields)
	if err != nil && !s.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && s.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	if s.checkFn != nil {
		s.checkFn(t, s.csrPEM, resp)
	}
}
