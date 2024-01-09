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
				} else {
					if test.err != err.Error() {
						t.Errorf("Expected error: %s but got: %s instead", err.Error(), test.err)
					}
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
		"should match if commonName is one of the requested requested dnsNames": {
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
		"should match if otherNames are equal": {
			spec: cmapi.CertificateSpec{
				OtherNames: []cmapi.OtherName{
					{
						OID:       "1.3.6.1.4.1.311.20.2.3",
						UTF8Value: "upn2@testdomain.local",
					},
					{
						OID:       "1.3.6.1.4.1.311.20.2.3",
						UTF8Value: "upn@testdomain.local",
					},
				},
			}, // openssl req -nodes -newkey rsa:2048 -subj "/CN=someCN" \
			// -addext 'subjectAltName=otherName:msUPN;UTF8:upn@testdomain.local,otherName:msUPN;UTF8:upn2@testdomain.local' -x509 |
			data: []byte(`-----BEGIN CERTIFICATE-----
MIIDOzCCAiOgAwIBAgIUJGyXr7GsoPVGC9PkG/QR5NQ3doQwDQYJKoZIhvcNAQEL
BQAwADAeFw0yNDAxMDkxMzQwNDZaFw0yNDAyMDgxMzQwNDZaMAAwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFVLGrwoVnLaVERh5l6/+Wc1bDrEOCrsZz
FUYOBJNpoJmbcl6Cp3DLyqrgkzAXWusUft77DmOpMz5C/2IWtI0Ju/NBg2wCwu6U
+NcL70WTx2h1v7fN0YHdzElGcO018bPpA9QEfzoB07G+G8dqTwUMrCq6qE5vbmY3
PywXfvCKbES4AFvQAcrm8qBOs4RPMlHp59gTAh9G3oVp1xJBoAHJr4CWbg65+ed9
d2YbVZjZ3aNbVGGc2Qp2vr9p/pcTtb1oyioCmryQmm3fIOMef6smn/LpFhnFoHUN
bJkBICG2JfHfygYkqukrhGFGv/UnVx7nmkeU5nooh7e0t5/cFbxzAgMBAAGjgaww
gakwHQYDVR0OBBYEFDIkbk6FammEuY6X2HODbctYOIHTMB8GA1UdIwQYMBaAFDIk
bk6FammEuY6X2HODbctYOIHTMA8GA1UdEwEB/wQFMAMBAf8wVgYDVR0RBE8wTaAk
BgorBgEEAYI3FAIDoBYMFHVwbkB0ZXN0ZG9tYWluLmxvY2FsoCUGCisGAQQBgjcU
AgOgFwwVdXBuMkB0ZXN0ZG9tYWluLmxvY2FsMA0GCSqGSIb3DQEBCwUAA4IBAQBq
jj/eTo0ZN6rNYPFYW3Uw4nZLasf3bEQlHG7QPJLaBvg87Yrt+1kWEzDhjlIK1bWi
ns56oLuaXIXjzF6KwkqBRLdqD/1bjPn7qX9uIhdncWs1Fi09mQMdI8Mnasx0IPOe
kosmem3A/RnylWmbaCLON/APhAXrPPbW1abI8gXyH5104T0470PY1CvR4Q6MTbXH
LCOnSiou3CO93H1Rnu9AWDXx5c6Fe1LO+AdaihdXLMAJN6NuMZRcXBChAo6d6/kh
/O44u3tp/z6trRdH+D8D68nyx/xjFqq2BFCfyau9T3KmFjZacUWXQv6tTpElFUlZ
7WkwZWxxkjzh9z529B9h
-----END CERTIFICATE-----`),
		},
		"should not match if OtherNames are not equal": {
			spec: cmapi.CertificateSpec{
				OtherNames: []cmapi.OtherName{
					{
						OID:       "1.3.6.1.4.1.311.20.2.3",
						UTF8Value: "upn@testdomain.local",
					},
				},
			},
			// generated with openssl with:  openssl req -nodes -newkey rsa:2048 -subj "/" \
			// -addext 'subjectAltName=otherName:msUPN;UTF8:ANOTHERUPN@testdomain.local' -x509
			data: []byte(`-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIULTMrWMewcF6XSc8hM6TnL9L8NrgwDQYJKoZIhvcNAQEL
BQAwADAeFw0yNDAxMDkxMzQyMTVaFw0yNDAyMDgxMzQyMTVaMAAwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCnIvWN7Nj/+bST7R1tmxu0olvjwgfPBhCp
/6OiPuANxZtYkQiqIx4KxnA5KErpQHzp9zlExE2FJUd5Fn83V5+we8/tXRT4mdVg
uOhVab8KHXciW2Ia0B6zdJakYL0qy6ol6kQDUansZi+0vBVbRzJIDAJLRSHGjXRT
BlYuZxgyOawD19vdBKDg3zz2vszQprSONM5qefnk0S3nbsIN3rPprifwjCjn+GMc
pcVXF1UizhyGFTxX7CiTNQg2sD6eAxvNHwyPfYo0cAWVXk1Ctoy+nGWX70zYQIw5
PI9+hagoFBy8AMhg2MgwAJV3Iay8JRnItCkE5xrh6XxMaGzBDTybAgMBAAGjgYww
gYkwHQYDVR0OBBYEFMjP9HapmDU06sI25oFVVX7h4mziMB8GA1UdIwQYMBaAFMjP
9HapmDU06sI25oFVVX7h4mziMA8GA1UdEwEB/wQFMAMBAf8wNgYDVR0RBC8wLaAr
BgorBgEEAYI3FAIDoB0MG0FOT1RIRVJVUE5AdGVzdGRvbWFpbi5sb2NhbDANBgkq
hkiG9w0BAQsFAAOCAQEAbQLZXPWqT78YmhWich59tiQ+3VStjamS/dI9qrgjo3CN
phYWiTe5anIv1tp2MOFD0eueO+zDLtSfFWLTBq4Qce+fDZK4WEPJrj9A/77WP55R
1IGvQVYhEAGVAiSFudp5loUx6LhcADcO45zWq/RBgWKDI4oUu744UZUJ5e68Vb/O
43QVvRF9qkte8X7LCBr1lX1mElh1d+qD2BiTuLzkMJeDNonmBfD1JM1zCZgYXCoE
20gLNilYVngZprTUOjjBYQMdrovC3XG2ByUTAXREyonQpmzRPKRnV+125kQooLXx
PvQpPM/KS8XNIJZXrbaEw0feitL6Pb+8+W5BHVcDkQ==
-----END CERTIFICATE-----`),
			violations: []string{"spec.otherNames"},
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
