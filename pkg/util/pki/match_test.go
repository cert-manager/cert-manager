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

package pki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func mustGenerateRSA(t *testing.T, keySize int) crypto.PrivateKey {
	pk, err := GenerateRSAPrivateKey(keySize)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func mustGenerateECDSA(t *testing.T, keySize int) crypto.PrivateKey {
	pk, err := GenerateECPrivateKey(keySize)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func mustGenerateEd25519(t *testing.T) crypto.PrivateKey {
	pk, err := GenerateEd25519PrivateKey()
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
		err          string
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
			key:          mustGenerateECDSA(t, ECCurve256),
			expectedAlgo: cmapi.ECDSAKeyAlgorithm,
			expectedSize: 256,
		},
		"should not match if ECDSA keySize is incorrect": {
			key:          mustGenerateECDSA(t, ECCurve256),
			expectedAlgo: cmapi.ECDSAKeyAlgorithm,
			expectedSize: ECCurve521,
			violations:   []string{"spec.privateKey.size"},
		},
		"should not match if keyAlgorithm is incorrect": {
			key:          mustGenerateECDSA(t, ECCurve256),
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
			violations, err := PrivateKeyMatchesSpec(
				test.key,
				cmapi.CertificateSpec{
					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: test.expectedAlgo,
						Size:      test.expectedSize,
					},
				},
			)
			switch {
			case err != nil:
				if test.err != err.Error() {
					t.Errorf("error text did not match, got=%s, exp=%s", err.Error(), test.err)
				}
			default:
				if test.err != "" {
					t.Errorf("got no error but expected: %s", test.err)
				}
			}
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
			crSpec: MustBuildCertificateRequest(&cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "cn",
				OtherNames: []cmapi.OtherName{
					{
						OID:       "1.3.6.1.4.1.311.20.2.3",
						UTF8Value: "upn@testdomain.local",
					},
				},
			}}, t),
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
			crSpec: MustBuildCertificateRequest(&cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "cn",
				OtherNames: []cmapi.OtherName{
					{
						OID:       "1.3.6.1.4.1.311.20.2.3",
						UTF8Value: "upn@testdomain.local",
					},
				},
			}}, t),
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
			crSpec: MustBuildCertificateRequest(&cmapi.Certificate{Spec: cmapi.CertificateSpec{
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
			}}, t),
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
			violations, err := RequestMatchesSpec(test.crSpec, test.certSpec)
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
		pk, err := GenerateRSAPrivateKey(2048)
		if err != nil {
			t.Fatal(err)
		}

		seq, err := UnmarshalSubjectStringToRDNSequence(literalSubject)
		if err != nil {
			t.Fatal(err)
		}

		asn1Seq, err := asn1.Marshal(seq)
		if err != nil {
			t.Fatal(err)
		}

		csr := &x509.CertificateRequest{
			RawSubject: asn1Seq,
		}

		csrBytes, err := x509.CreateCertificateRequest(bytes.NewBuffer(nil), csr, pk)
		if err != nil {
			t.Fatal(err)
		}

		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
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
		test := test
		t.Run(test.name, func(t *testing.T) {
			violations, err := RequestMatchesSpec(
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

func TestSecretDataAltNamesMatchSpec(t *testing.T) {
	tests := map[string]struct {
		data       []byte
		spec       cmapi.CertificateSpec
		err        string
		violations []string
	}{
		"should match if common name and dns names exactly equal": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			}),
		},
		"should match if commonName is missing but is present in dnsNames": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				DNSNames: []string{"cn", "at", "least", "one"},
			}),
		},
		"should match if commonName is missing but is present in dnsNames (not first)": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one", "cn"},
			}),
		},
		"should match if commonName is one of the requested dnsNames": {
			spec: cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "at",
				DNSNames:   []string{"least", "one"},
			}),
		},
		"should not match if commonName is not present on certificate": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one"},
			}),
			violations: []string{"spec.commonName"},
		},
		"should report violation for both commonName and dnsNames if both are missing": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one", "other"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one"},
			}),
			violations: []string{"spec.commonName", "spec.dnsNames"},
		},
		"should report violation for both commonName and dnsNames if not requested": {
			spec: cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
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
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one", "other"},
			}),
			violations: []string{"spec.dnsNames"},
		},
		"should match if commonName is a duplicated dnsName (but not requested)": {
			spec: cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "at",
				DNSNames:   []string{"at", "least", "one"},
			}),
		},
		"should match if commonName is a duplicated dnsName": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "at",
				DNSNames:   []string{"at", "least", "one", "cn"},
			}),
		},
		"should match if ipAddresses are equal": {
			spec: cmapi.CertificateSpec{
				IPAddresses: []string{"127.0.0.1"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				IPAddresses: []string{"127.0.0.1"},
			}),
		},
		"should not match if ipAddresses are not equal": {
			spec: cmapi.CertificateSpec{
				IPAddresses: []string{"127.0.0.1"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				IPAddresses: []string{"127.0.2.1"},
			}),
			violations: []string{"spec.ipAddresses"},
		},
		"should not match if ipAddresses has been made the commonName": {
			spec: cmapi.CertificateSpec{
				IPAddresses: []string{"127.0.0.1"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName:  "127.0.0.1",
				IPAddresses: []string{"127.0.0.1"},
			}),
			violations: []string{"spec.commonName"},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			violations, err := SecretDataAltNamesMatchSpec(&corev1.Secret{Data: map[string][]byte{corev1.TLSCertKey: test.data}}, test.spec)
			switch {
			case err != nil:
				if test.err != err.Error() {
					t.Errorf("error text did not match, got=%s, exp=%s", err.Error(), test.err)
				}
			default:
				if test.err != "" {
					t.Errorf("got no error but expected: %s", test.err)
				}
			}
			if !reflect.DeepEqual(violations, test.violations) {
				t.Errorf("violations did not match, got=%s, exp=%s", violations, test.violations)
			}
		})
	}
}

func selfSignCertificate(t *testing.T, spec cmapi.CertificateSpec) []byte {
	pk, err := GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	template, err := CertificateTemplateFromCertificate(&cmapi.Certificate{Spec: spec})
	if err != nil {
		t.Fatal(err)
	}

	pemData, _, err := SignCertificate(template, template, pk.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}

	return pemData
}

func MustBuildCertificateRequest(crt *cmapi.Certificate, t *testing.T) *cmapi.CertificateRequest {
	pk, err := GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	csrTemplate, err := GenerateCSR(crt, WithOtherNames(true))
	if err != nil {
		t.Fatal(err)
	}

	var buffer bytes.Buffer
	csr, err := x509.CreateCertificateRequest(&buffer, csrTemplate, pk)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
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
