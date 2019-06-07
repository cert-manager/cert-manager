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
	"reflect"
	"testing"

	"github.com/Venafi/vcert/pkg/endpoint"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
	"github.com/kr/pretty"
)

func checkCertificateIssued(t *testing.T, s *fixture, args ...interface{}) {
	returnedCert := args[0].(*cmapi.Certificate)
	resp := args[1].(*issuer.IssueResponse)

	if resp == nil {
		t.Errorf("expected IssueResponse to be non-nil")
		t.FailNow()
		return
	}
	if err, ok := args[2].(error); ok && err != nil {
		t.Errorf("expected no error to be returned, but got: %v", err)
		return
	}
	if !reflect.DeepEqual(returnedCert, s.Certificate) {
		t.Errorf("output was not as expected: %s", pretty.Diff(returnedCert, s.Certificate))
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
	expectedCN := pki.CommonNameForCertificate(s.Certificate)
	if expectedCN != crt.Subject.CommonName {
		t.Errorf("expected common name to be %q but it was %q", expectedCN, crt.Subject.CommonName)
	}

	// validate the dns names are correct
	expectedDNSNames := pki.DNSNamesForCertificate(s.Certificate)
	if !util.EqualUnsorted(crt.DNSNames, expectedDNSNames) {
		t.Errorf("expected dns names to be %q but it was %q", expectedDNSNames, crt.DNSNames)
	}
}

func TestIssue(t *testing.T) {
	tests := map[string]fixture{
		"obtain a certificate with a single dnsname specified": {
			Certificate: gen.Certificate("testcrt",
				gen.SetCertificateDNSNames("example.com"),
			),
			CheckFn: checkCertificateIssued,
			Err:     false,
		},
		"obtain a certificate with the organization field locked by the venafi zone": {
			Certificate: gen.Certificate("testcrt",
				gen.SetCertificateDNSNames("example.com"),
			),
			Client: fakeConnector{
				ReadZoneConfigurationFunc: func() (*endpoint.ZoneConfiguration, error) {
					return &endpoint.ZoneConfiguration{
						Organization: "testing-org",
					}, nil
				},
			}.Default(),
			CheckFn: func(t *testing.T, s *fixture, args ...interface{}) {
				checkCertificateIssued(t, s, args...)
				resp := args[1].(*issuer.IssueResponse)
				x509Cert, err := pki.DecodeX509CertificateBytes(resp.Certificate)
				if err != nil {
					t.Errorf("could not decode x509 certificate bytes: %v", err)
				}
				if x509Cert.Subject.Organization[0] != "testing-org" {
					t.Errorf("expected organization field to be 'testing-org' but got: %s", x509Cert.Subject.Organization[0])
				}
			},
			Err: false,
		},
		"obtain a certificate with the organization field defaulted by the venafi zone": {
			Certificate: gen.Certificate("testcrt",
				gen.SetCertificateDNSNames("example.com"),
			),
			Client: fakeConnector{
				ReadZoneConfigurationFunc: func() (*endpoint.ZoneConfiguration, error) {
					return &endpoint.ZoneConfiguration{
						Organization: "testing-org",
					}, nil
				},
			}.Default(),
			CheckFn: func(t *testing.T, s *fixture, args ...interface{}) {
				checkCertificateIssued(t, s, args...)

				resp := args[1].(*issuer.IssueResponse)
				x509Cert, err := pki.DecodeX509CertificateBytes(resp.Certificate)
				if err != nil {
					t.Errorf("could not decode x509 certificate bytes: %v", err)
				}
				if x509Cert.Subject.Organization[0] != "testing-org" {
					t.Errorf("expected organization field to be 'testing-org' but got: %s", x509Cert.Subject.Organization[0])
				}
			},
			Err: false,
		},
		"obtain a certificate with the organization field set by the certificate": {
			Certificate: gen.Certificate("testcrt",
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateOrganization("testing-crt-org"),
			),
			CheckFn: func(t *testing.T, s *fixture, args ...interface{}) {
				checkCertificateIssued(t, s, args...)
				resp := args[1].(*issuer.IssueResponse)
				x509Cert, err := pki.DecodeX509CertificateBytes(resp.Certificate)
				if err != nil {
					t.Errorf("could not decode x509 certificate bytes: %v", err)
				}
				if x509Cert.Subject.Organization[0] != "testing-crt-org" {
					t.Errorf("expected organization field to be 'testing-crt-org' but got: %s", x509Cert.Subject.Organization[0])
				}
			},
			Err: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.Builder == nil {
				test.Builder = &testpkg.Builder{}
			}
			test.Setup(t)
			certCopy := test.Certificate.DeepCopy()
			resp, err := test.Venafi.Issue(test.Ctx, certCopy)
			if err != nil && !test.Err {
				t.Errorf("Expected function to not error, but got: %v", err)
			}
			if err == nil && test.Err {
				t.Errorf("Expected function to get an error, but got: %v", err)
			}
			test.Finish(t, certCopy, resp, err)
		})
	}
}
