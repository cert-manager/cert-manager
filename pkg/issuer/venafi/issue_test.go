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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Venafi/vcert/pkg/endpoint"
	corelisters "k8s.io/client-go/listers/core/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	controllertest "github.com/jetstack/cert-manager/pkg/controller/test"
	internalvenafi "github.com/jetstack/cert-manager/pkg/internal/venafi"
	internalvenafifake "github.com/jetstack/cert-manager/pkg/internal/venafi/fake"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func checkCertificateIssued(t *testing.T, cert *cmapi.Certificate, resp *issuer.IssueResponse) {
	if resp == nil {
		t.Errorf("expected IssueResponse to be non-nil")
		t.FailNow()
		return
	}

	pk, err := pki.DecodePrivateKeyBytes(resp.PrivateKey)
	if err != nil {
		t.Errorf("unable to decode private key: %v", err)
		return
	}
	crt, err := pki.DecodeX509CertificateBytes(resp.Certificate)
	if err != nil {
		t.Errorf("unable to decode x509 certificate: %v", err)
		return
	}
	ok, err := pki.PublicKeyMatchesCertificate(pk.Public(), crt)
	if err != nil {
		t.Errorf("error checking private key: %v", err)
		return
	}
	if !ok {
		t.Errorf("private key does not match certificate")
	}
	// validate the common name is correct
	expectedCN := pki.CommonNameForCertificate(cert)
	if expectedCN != crt.Subject.CommonName {
		t.Errorf("expected common name to be %q but it was %q", expectedCN, crt.Subject.CommonName)
	}

	// validate the dns names are correct
	expectedDNSNames := pki.DNSNamesForCertificate(cert)
	if !util.EqualUnsorted(crt.DNSNames, expectedDNSNames) {
		t.Errorf("expected dns names to be %q but it was %q", expectedDNSNames, crt.DNSNames)
	}
}
func checkIssueResponseNil(t *testing.T, cert *cmapi.Certificate, resp *issuer.IssueResponse) {
	if resp != nil {
		t.Errorf("expected response to be nil but got=%+v", resp)
	}
}

func TestIssue(t *testing.T) {
	commonName := "test-common-name"
	dnsNames := []string{"foo.example.com", "bar.example.com"}

	baseEvent := []string{
		"Normal Issuing Requesting new certificate...",
	}
	baseWithGenEvents := append(baseEvent,
		[]string{
			"Normal GenerateKey Generated new private key",
		}...)

	baseCertificate := gen.Certificate("test-cert",
		gen.SetCertificateCommonName(commonName),
		gen.SetCertificateDNSNames(dnsNames...),
		gen.SetCertificateKeyAlgorithm(cmapi.RSAKeyAlgorithm),
	)

	failingClientBuilder := func(string, corelisters.SecretLister,
		cmapi.GenericIssuer) (internalvenafi.Interface, error) {
		return nil, errors.New("this is an error")
	}

	clientBuilderBackedByFakeVenafi := func(string, corelisters.SecretLister,
		cmapi.GenericIssuer) (internalvenafi.Interface, error) {
		return &internalvenafifake.Venafi{
			SignFn: func(csr []byte, duration time.Duration) ([]byte, error) {
				client := internalvenafifake.Connector{
					ReadZoneConfigurationFunc: func() (*endpoint.ZoneConfiguration, error) {
						return &endpoint.ZoneConfiguration{
							Organization: "testing-org",
						}, nil
					},
				}.Default()

				v := new(internalvenafi.Venafi)
				v.SetClient(client)
				return v.Sign(csr, duration)
			},
		}, nil
	}

	tests := map[string]testIssueT{
		"if fail to generate private key from Certificate then fail and return no error": {
			crt: gen.CertificateFrom(baseCertificate,
				gen.SetCertificateKeyAlgorithm("foo"),
			),
			expectedEvents: append(baseEvent,
				"Warning PrivateKeyError Error generating certificate private key: unsupported private key algorithm specified: foo",
			),
			expectedErr: false,
			checkFn:     checkIssueResponseNil,
		},
		"if fail to generate template from certificate then return error": {
			crt: gen.CertificateFrom(baseCertificate,
				gen.SetCertificateCommonName(""),
				gen.SetCertificateDNSNames(),
			),
			expectedEvents: baseWithGenEvents,
			expectedErr:    true,
			checkFn:        checkIssueResponseNil,
		},
		"if fail to build client then return with error": {
			crt:           baseCertificate,
			clientBuilder: failingClientBuilder,
			expectedEvents: append(baseWithGenEvents,
				"Warning FailedInit Failed to create Venafi client: this is an error"),
			expectedErr: true,
			checkFn:     checkIssueResponseNil,
		},
		"if sign returns a pending error, return error": {
			crt: baseCertificate,
			clientBuilder: func(string, corelisters.SecretLister,
				cmapi.GenericIssuer) (internalvenafi.Interface, error) {
				return &internalvenafifake.Venafi{
					SignFn: func([]byte, time.Duration) ([]byte, error) {
						return nil, endpoint.ErrCertificatePending{
							CertificateID: "cert-id",
							Status:        "pending",
						}
					},
				}, nil
			},
			expectedEvents: append(baseWithGenEvents,
				"Warning Retrieve Failed to retrieve a certificate from Venafi, still pending: Issuance is pending. You may try retrieving the certificate later using Pickup ID: cert-id\n\tStatus: pending"),
			expectedErr: true,
			checkFn:     checkIssueResponseNil,
		},
		"if sign returns a timeout error, return error": {
			crt: baseCertificate,
			clientBuilder: func(string, corelisters.SecretLister,
				cmapi.GenericIssuer) (internalvenafi.Interface, error) {
				return &internalvenafifake.Venafi{
					SignFn: func([]byte, time.Duration) ([]byte, error) {
						return nil, endpoint.ErrRetrieveCertificateTimeout{
							CertificateID: "cert-id",
						}
					},
				}, nil
			},
			expectedEvents: append(baseWithGenEvents,
				"Warning Retrieve Failed to retrieve a certificate from Venafi, timed out: Operation timed out. You may try retrieving the certificate later using Pickup ID: cert-id"),
			expectedErr: true,
			checkFn:     checkIssueResponseNil,
		},
		"if sign returns a generic error, return error": {
			crt: baseCertificate,
			clientBuilder: func(string, corelisters.SecretLister,
				cmapi.GenericIssuer) (internalvenafi.Interface, error) {
				return &internalvenafifake.Venafi{
					SignFn: func([]byte, time.Duration) ([]byte, error) {
						return nil, errors.New("sign error")
					},
				}, nil
			},
			expectedEvents: append(baseWithGenEvents,
				"Warning Retrieve Failed to retrieve a certificate from Venafi: sign error"),
			expectedErr: true,
			checkFn:     checkIssueResponseNil,
		},
		"obtain a certificate with a single dnsname specified": {
			crt: gen.CertificateFrom(baseCertificate,
				gen.SetCertificateDNSNames("example.com"),
			),
			clientBuilder: clientBuilderBackedByFakeVenafi,
			checkFn:       checkCertificateIssued,
			expectedEvents: append(baseWithGenEvents,
				"Normal Retrieve Retrieved certificate from Venafi server"),
			expectedErr: false,
		},
		"obtain a certificate with a two dnsnames specified": {
			crt: gen.CertificateFrom(baseCertificate,
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateOrganization("testing-crt-org"),
			),
			clientBuilder: clientBuilderBackedByFakeVenafi,
			expectedEvents: append(baseWithGenEvents,
				"Normal Retrieve Retrieved certificate from Venafi server"),
			expectedErr: false,
			checkFn:     checkCertificateIssued,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.runTest(t)
		})
	}
}

type testIssueT struct {
	crt           *cmapi.Certificate
	clientBuilder internalvenafi.VenafiClientBuilder
	secretLister  corelisters.SecretLister
	iss           cmapi.GenericIssuer

	expectedErr    bool
	expectedEvents []string

	checkFn func(*testing.T, *cmapi.Certificate, *issuer.IssueResponse)
}

func (i *testIssueT) runTest(t *testing.T) {
	rec := &controllertest.FakeRecorder{}
	v := &Venafi{
		resourceNamespace: "test-namespace",
		Context: &controller.Context{
			Recorder: rec,
		},
		clientBuilder: i.clientBuilder,
	}

	resp, err := v.Issue(context.Background(), i.crt)
	if err != nil && !i.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && i.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	if !util.EqualSorted(i.expectedEvents, rec.Events) {
		t.Errorf("got unexpected events, exp='%s' got='%s'",
			i.expectedEvents, rec.Events)
	}

	if i.checkFn != nil {
		i.checkFn(t, i.crt, resp)
	}
}
