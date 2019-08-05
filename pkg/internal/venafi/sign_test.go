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
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/Venafi/vcert/pkg/venafi/fake"

	//"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	//"github.com/jetstack/cert-manager/test/unit/gen"
)

func checkCertificateIssued(t *testing.T, csrPEM []byte, resp []byte, err error) {
	if len(resp) == 0 {
		t.Errorf("expected IssueResponse to be non-nil")
		t.FailNow()
		return
	}

	if err != nil {
		t.Errorf("expected no error to be returned, but got: %v", err)
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

func generateCSR(t *testing.T, sk crypto.Signer, commonName string, dnsNames []string) []byte {
	asn1Subj, _ := asn1.Marshal(pkix.Name{
		CommonName: commonName,
	}.ToRDNSequence())
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
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

	tests := map[string]testT{
		"obtain a certificate with a single dnsname specified": {
			csrPEM:      csrPEM,
			CheckFn:     checkCertificateIssued,
			expectedErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			runTest(t, test)
		})
	}
}

type testT struct {
	csrPEM []byte
	client connector

	expectedErr bool

	CheckFn func(*testing.T, []byte, []byte, error)
}

func runTest(t *testing.T, test testT) {
	if test.client == nil {
		test.client = fake.NewConnector(true, nil)
	}

	v := &Venafi{
		client: test.client,
	}

	resp, err := v.Sign(test.csrPEM)
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	if test.CheckFn != nil {
		test.CheckFn(t, test.csrPEM, resp, err)
	}
}
