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

package pki_test

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func mustGenerateRSA(t *testing.T, keySize int) crypto.PrivateKey {
	pk, err := pki.GenerateRSAPrivateKey(keySize)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func mustGenerateECDSA(t *testing.T, keySize int) crypto.PrivateKey {
	pk, err := pki.GenerateECPrivateKey(keySize)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func mustGenerateEd25519(t *testing.T) crypto.PrivateKey {
	pk, err := pki.GenerateEd25519PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func TestPrivateKeyMatchesSpec(t *testing.T) {
	tests := map[string]struct {
		key          crypto.PrivateKey
		expectedAlgo cmapi.PrivateKeyAlgorithm
		expectedSize int
		violations   []string
	}{
		"should match if keySize and algorithm are correct (RSA)": {
			key:          mustGenerateRSA(t, 2048),
			expectedAlgo: cmapi.RSAKeyAlgorithm,
			expectedSize: 2048,
		},
		"should not match if RSA keySize is incorrect": {
			key:          mustGenerateRSA(t, 2048),
			expectedAlgo: cmapi.RSAKeyAlgorithm,
			expectedSize: 4096,
			violations:   []string{"spec.privateKey.size"},
		},
		"should match if keySize and algorithm are correct (ECDSA)": {
			key:          mustGenerateECDSA(t, pki.ECCurve256),
			expectedAlgo: cmapi.ECDSAKeyAlgorithm,
			expectedSize: 256,
		},
		"should not match if ECDSA keySize is incorrect": {
			key:          mustGenerateECDSA(t, pki.ECCurve256),
			expectedAlgo: cmapi.ECDSAKeyAlgorithm,
			expectedSize: pki.ECCurve521,
			violations:   []string{"spec.privateKey.size"},
		},
		"should not match if keyAlgorithm is incorrect": {
			key:          mustGenerateECDSA(t, pki.ECCurve256),
			expectedAlgo: cmapi.RSAKeyAlgorithm,
			expectedSize: 2048,
			violations:   []string{"spec.privateKey.algorithm"},
		},
		"should match if keySize and algorithm are correct (Ed25519)": {
			key:          mustGenerateEd25519(t),
			expectedAlgo: cmapi.Ed25519KeyAlgorithm,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			violations := pki.PrivateKeyMatchesSpec(
				test.key,
				cmapi.CertificateSpec{
					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: test.expectedAlgo,
						Size:      test.expectedSize,
					},
				},
			)
			if !reflect.DeepEqual(violations, test.violations) {
				t.Errorf("violations did not match, got=%s, exp=%s", violations, test.violations)
			}
		})
	}
}

func TestCertificateRequestOtherNamesMatchSpec(t *testing.T) {
	tests := map[string]struct {
		crSpec     *cmapi.CertificateRequest
		certSpec   cmapi.CertificateSpec
		err        string
		violations []string
	}{
		"should not report any violation if Certificate otherName(s) match the CertificateRequest's": {
			crSpec: mustBuildCertificateRequest(t, &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "cn",
				OtherNames: []cmapi.OtherName{
					{
						OID:       "1.3.6.1.4.1.311.20.2.3",
						UTF8Value: "upn@testdomain.local",
					},
				},
			}}),
			certSpec: cmapi.CertificateSpec{
				CommonName: "cn",
				OtherNames: []cmapi.OtherName{
					{
						OID:       "1.3.6.1.4.1.311.20.2.3",
						UTF8Value: "upn@testdomain.local",
					},
				},
			},
			err: "",
		},
		"should report violation if Certificate otherName(s) mismatch the CertificateRequest's": {
			crSpec: mustBuildCertificateRequest(t, &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "cn",
				OtherNames: []cmapi.OtherName{
					{
						OID:       "1.3.6.1.4.1.311.20.2.3",
						UTF8Value: "upn@testdomain.local",
					},
				},
			}}),
			certSpec: cmapi.CertificateSpec{
				CommonName: "cn",
				OtherNames: []cmapi.OtherName{
					{
						OID:       "1.3.6.1.4.1.311.20.2.3",
						UTF8Value: "upn2@testdomain.local",
					},
				},
			},
			err: "",
			violations: []string{
				"spec.otherNames",
			},
		},
		"should not report violation if Certificate otherName(s) match the CertificateRequest's (with different order)": {
			crSpec: mustBuildCertificateRequest(t, &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "cn",
				OtherNames: []cmapi.OtherName{
					{
						OID:       "1.3.6.1.4.1.311.20.2.3",
						UTF8Value: "anotherupn@testdomain.local",
					},
					{
						OID:       "1.3.6.1.4.1.311.20.2.3",
						UTF8Value: "upn@testdomain.local",
					},
				},
			}}),
			certSpec: cmapi.CertificateSpec{
				CommonName: "cn",
				OtherNames: []cmapi.OtherName{
					{
						OID:       "1.3.6.1.4.1.311.20.2.3",
						UTF8Value: "upn@testdomain.local",
					},
					{
						OID:       "1.3.6.1.4.1.311.20.2.3",
						UTF8Value: "anotherupn@testdomain.local",
					},
				},
			},
			err: "",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			violations, err := pki.RequestMatchesSpec(test.crSpec, test.certSpec)
			if err != nil {
				if test.err == "" {
					t.Errorf("Unexpected error: %s", err.Error())
				} else if test.err != err.Error() {
					t.Errorf("Expected error: %s but got: %s instead", err.Error(), test.err)
				}
			}

			if !reflect.DeepEqual(violations, test.violations) {
				t.Errorf("violations did not match, got=%s, exp=%s", violations, test.violations)
			}
		})
	}
}

func TestRequestMatchesSpecSubject(t *testing.T) {
	createCSRBlob := func(literalSubject string) []byte {
		seq, err := pki.UnmarshalSubjectStringToRDNSequence(literalSubject)
		if err != nil {
			t.Fatal(err)
		}

		asn1Seq, err := asn1.Marshal(seq)
		if err != nil {
			t.Fatal(err)
		}

		pemBytes, _, err := gen.CSR(x509.Ed25519, func(cr *x509.CertificateRequest) error {
			cr.RawSubject = asn1Seq
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		return pemBytes
	}

	tests := []struct {
		name           string
		subject        *cmapi.X509Subject
		literalSubject string
		x509CSR        []byte
		err            string
		violations     []string
	}{
		{
			name:           "Matching LiteralSubjects",
			literalSubject: "CN=example.com,OU=example,O=example,L=example,ST=example,C=US",
			x509CSR:        createCSRBlob("CN=example.com,OU=example,O=example,L=example,ST=example,C=US"),
		},
		{
			name:           "Matching LiteralSubjects",
			literalSubject: "ST=example,C=US",
			x509CSR:        createCSRBlob("ST=example"),
			violations:     []string{"spec.literalSubject"},
		},
		{
			name:           "Matching LiteralSubjects",
			literalSubject: "ST=example,C=US,O=#04024869",
			x509CSR:        createCSRBlob("ST=example,C=US,O=#04024869"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			violations, err := pki.RequestMatchesSpec(
				&cmapi.CertificateRequest{
					Spec: cmapi.CertificateRequestSpec{
						Request: test.x509CSR,
					},
				},
				cmapi.CertificateSpec{
					Subject:        test.subject,
					LiteralSubject: test.literalSubject,
				},
			)
			if err != nil {
				if test.err == "" {
					t.Errorf("Unexpected error: %s", err.Error())
				} else if test.err != err.Error() {
					t.Errorf("Expected error: %s but got: %s instead", err.Error(), test.err)
				}
			}

			if !reflect.DeepEqual(violations, test.violations) {
				t.Errorf("violations did not match, got=%s, exp=%s", violations, test.violations)
			}
		})
	}
}

// RequestMatchesSpecIssuerRef tests that RequestMatchesSpec correctly compares
// the IssuerRef in the CertificateRequest and CertificateSpec.
//
// cert-manager 1.19 introduced API defaults for the IssuerRef Kind and Group
// fields for Certificate resources only; not for CertificateRequest resources.
// This means that when cert-manager fetches existing Certificate resource which
// have an empty Kind and/or Group field in the IssuerRef, the Kubernetes API
// server will default these fields to "Issuer" and "cert-manager.io"
// respectively in the Certificate resource only. The Kind and Group fields in
// the IssuerRef of the *existing* CertificateRequest resource will remain
// empty. Therefore, RequestMatchesSpec needs to treat empty Kind and Group
// fields in the IssuerRef of the CertificateRequest as equivalent to "Issuer"
// and "cert-manager.io" respectively when comparing against the IssuerRef in
// the CertificateSpec, otherwise cert-manager will re-issue all Certificates
// after an upgrade to 1.19.
func TestRequestMatchesSpecIssuerRef(t *testing.T) {
	type testCase struct {
		crSpec     *cmapi.CertificateRequest
		certSpec   cmapi.CertificateSpec
		err        string
		violations []string
	}

	tests := map[string]testCase{
		"should not report any violation if Certificate issuerRef matches the CertificateRequest's": {
			crSpec: mustBuildCertificateRequest(t, &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "dummy-common-name",
				IssuerRef: cmmeta.IssuerReference{
					Name:  "test-issuer",
					Kind:  "Issuer",
					Group: "cert-manager.io",
				},
			}}),
			certSpec: cmapi.CertificateSpec{
				CommonName: "dummy-common-name",
				IssuerRef: cmmeta.IssuerReference{
					Name:  "test-issuer",
					Kind:  "Issuer",
					Group: "cert-manager.io",
				},
			},
			err: "",
		},
		"should not report any violation if both Certificate and CertificateRequest issuerRef Kind and Group are empty": {
			crSpec: mustBuildCertificateRequest(t, &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "dummy-common-name",
				IssuerRef: cmmeta.IssuerReference{
					Name: "test-issuer",
				},
			}}),
			certSpec: cmapi.CertificateSpec{
				CommonName: "dummy-common-name",
				IssuerRef: cmmeta.IssuerReference{
					Name: "test-issuer",
				},
			},
			err: "",
		},
		"should not report any violation if Certificate issuerRef Kind and Group are defaulted and CertificateRequest issuerRef Group is empty": {
			crSpec: mustBuildCertificateRequest(t, &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "dummy-common-name",
				IssuerRef: cmmeta.IssuerReference{
					Name: "test-issuer",
					Kind: "Issuer",
				},
			}}),
			certSpec: cmapi.CertificateSpec{
				CommonName: "dummy-common-name",
				IssuerRef: cmmeta.IssuerReference{
					Name:  "test-issuer",
					Kind:  "Issuer",
					Group: "cert-manager.io",
				},
			},
			err: "",
		},
		"should not report any violation if Certificate issuerRef Kind and Group are defaulted and CertificateRequest issuerRef Kind is empty": {
			crSpec: mustBuildCertificateRequest(t, &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "dummy-common-name",
				IssuerRef: cmmeta.IssuerReference{
					Name:  "test-issuer",
					Group: "cert-manager.io",
				},
			}}),
			certSpec: cmapi.CertificateSpec{
				CommonName: "dummy-common-name",
				IssuerRef: cmmeta.IssuerReference{
					Name:  "test-issuer",
					Kind:  "Issuer",
					Group: "cert-manager.io",
				},
			},
			err: "",
		},
		"should report violation if Certificate issuerRef name mismatches the CertificateRequest's": {
			crSpec: mustBuildCertificateRequest(t, &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "dummy-common-name",
				IssuerRef: cmmeta.IssuerReference{
					Name:  "test-issuer",
					Kind:  "Issuer",
					Group: "cert-manager.io",
				},
			}}),
			certSpec: cmapi.CertificateSpec{
				CommonName: "dummy-common-name",
				IssuerRef: cmmeta.IssuerReference{
					Name:  "different-issuer",
					Kind:  "Issuer",
					Group: "cert-manager.io",
				},
			},
			err:        "",
			violations: []string{"spec.issuerRef"},
		},
		"should not report any violation if Certificate issuerRef Kind and Group are defaulted and CertificateRequest's are empty": {
			crSpec: mustBuildCertificateRequest(t, &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "dummy-common-name",
				IssuerRef: cmmeta.IssuerReference{
					Name: "test-issuer",
				},
			}}),
			certSpec: cmapi.CertificateSpec{
				CommonName: "dummy-common-name",
				IssuerRef: cmmeta.IssuerReference{
					Name:  "test-issuer",
					Kind:  "Issuer",
					Group: "cert-manager.io",
				},
			},
			err: "",
		},
		"should report violation if Certificate issuerRef Kind mismatches the CertificateRequest's (defaulted vs non-defaulted)": {
			crSpec: mustBuildCertificateRequest(t, &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "dummy-common-name",
				IssuerRef: cmmeta.IssuerReference{
					Name:  "test-issuer",
					Kind:  "ClusterIssuer",
					Group: "cert-manager.io",
				},
			}}),
			certSpec: cmapi.CertificateSpec{
				CommonName: "dummy-common-name",
				IssuerRef: cmmeta.IssuerReference{
					Name:  "test-issuer",
					Kind:  "Issuer",
					Group: "cert-manager.io",
				},
			},
			err:        "",
			violations: []string{"spec.issuerRef"},
		},
		"should report violation if Certificate issuerRef Group mismatches the CertificateRequest's (defaulted vs non-defaulted)": {
			crSpec: mustBuildCertificateRequest(t, &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "dummy-common-name",
				IssuerRef: cmmeta.IssuerReference{
					Name:  "test-issuer",
					Kind:  "Issuer",
					Group: "different-group.io",
				},
			}}),
			certSpec: cmapi.CertificateSpec{
				CommonName: "dummy-common-name",
				IssuerRef: cmmeta.IssuerReference{
					Name:  "test-issuer",
					Kind:  "Issuer",
					Group: "cert-manager.io",
				},
			},
			err:        "",
			violations: []string{"spec.issuerRef"},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			violations, err := pki.RequestMatchesSpec(test.crSpec, test.certSpec)
			if test.err != "" {
				assert.EqualError(t, err, test.err)
				assert.Empty(t, violations)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.violations, violations)
		})
	}
}

func TestFuzzyX509AltNamesMatchSpec(t *testing.T) {
	tests := map[string]struct {
		x509       *x509.Certificate
		spec       cmapi.CertificateSpec
		violations []string
	}{
		"should match if common name and dns names exactly equal": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			x509: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			}),
		},
		"should match if commonName is missing but is present in dnsNames": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			x509: selfSignCertificate(t, cmapi.CertificateSpec{
				DNSNames: []string{"cn", "at", "least", "one"},
			}),
		},
		"should match if commonName is missing but is present in dnsNames (not first)": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			x509: selfSignCertificate(t, cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one", "cn"},
			}),
		},
		"should match if commonName is one of the requested dnsNames": {
			spec: cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one"},
			},
			x509: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "at",
				DNSNames:   []string{"least", "one"},
			}),
		},
		"should not match if commonName is not present on certificate": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			x509: selfSignCertificate(t, cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one"},
			}),
			violations: []string{"spec.commonName"},
		},
		"should report violation for both commonName and dnsNames if both are missing": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one", "other"},
			},
			x509: selfSignCertificate(t, cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one"},
			}),
			violations: []string{"spec.commonName", "spec.dnsNames"},
		},
		"should report violation for both commonName and dnsNames if not requested": {
			spec: cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one"},
			},
			x509: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one", "other"},
			}),
			violations: []string{"spec.commonName", "spec.dnsNames"},
		},
		"should not match if certificate has more dnsNames than spec": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			x509: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one", "other"},
			}),
			violations: []string{"spec.dnsNames"},
		},
		"should match if commonName is a duplicated dnsName (but not requested)": {
			spec: cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one"},
			},
			x509: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "at",
				DNSNames:   []string{"at", "least", "one"},
			}),
		},
		"should match if commonName is a duplicated dnsName": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			x509: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "at",
				DNSNames:   []string{"at", "least", "one", "cn"},
			}),
		},
		"should match if ipAddresses are equal": {
			spec: cmapi.CertificateSpec{
				IPAddresses: []string{"127.0.0.1"},
			},
			x509: selfSignCertificate(t, cmapi.CertificateSpec{
				IPAddresses: []string{"127.0.0.1"},
			}),
		},
		"should not match if ipAddresses are not equal": {
			spec: cmapi.CertificateSpec{
				IPAddresses: []string{"127.0.0.1"},
			},
			x509: selfSignCertificate(t, cmapi.CertificateSpec{
				IPAddresses: []string{"127.0.2.1"},
			}),
			violations: []string{"spec.ipAddresses"},
		},
		"should not match if ipAddresses has been made the commonName": {
			spec: cmapi.CertificateSpec{
				IPAddresses: []string{"127.0.0.1"},
			},
			x509: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName:  "127.0.0.1",
				IPAddresses: []string{"127.0.0.1"},
			}),
			violations: []string{"spec.commonName"},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			violations := pki.FuzzyX509AltNamesMatchSpec(test.x509, test.spec)
			if !reflect.DeepEqual(violations, test.violations) {
				t.Errorf("violations did not match, got=%s, exp=%s", violations, test.violations)
			}
		})
	}
}

func selfSignCertificate(t *testing.T, spec cmapi.CertificateSpec) *x509.Certificate {
	template, err := pki.CertificateTemplateFromCertificate(&cmapi.Certificate{Spec: spec})
	if err != nil {
		t.Fatal(err)
	}

	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	// Marshal and unmarshal to ensure all fields are set correctly
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pk.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

func mustBuildCertificateRequest(t *testing.T, crt *cmapi.Certificate) *cmapi.CertificateRequest {
	pemData, _, err := gen.CSRForCertificate(crt)
	if err != nil {
		t.Fatal(err)
	}

	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        t.Name(),
			Annotations: crt.Annotations,
			Labels:      crt.Labels,
		},
		Spec: cmapi.CertificateRequestSpec{
			Request:   pemData,
			Duration:  crt.Spec.Duration,
			IssuerRef: crt.Spec.IssuerRef,
			IsCA:      crt.Spec.IsCA,
			Usages:    crt.Spec.Usages,
		},
	}

	return cr
}
