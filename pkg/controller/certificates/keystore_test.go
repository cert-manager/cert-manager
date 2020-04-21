/*
Copyright 2020 The Jetstack cert-manager contributors.

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
	"testing"

	jks "github.com/pavel-v-chernykh/keystore-go"
	"software.sslmate.com/src/go-pkcs12"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

func mustGeneratePrivateKey(t *testing.T, encoding cmapi.KeyEncoding) []byte {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	pkBytes, err := pki.EncodePrivateKey(pk, encoding)
	if err != nil {
		t.Fatal(err)
	}
	return pkBytes
}

func mustSelfSignCertificate(t *testing.T, pkBytes []byte) []byte {
	if pkBytes == nil {
		pkBytes = mustGeneratePrivateKey(t, cmapi.PKCS8)
	}
	pk, err := pki.DecodePrivateKeyBytes(pkBytes)
	if err != nil {
		t.Fatal(err)
	}
	x509Crt, err := pki.GenerateTemplate(&cmapi.Certificate{
		Spec: cmapi.CertificateSpec{
			DNSNames: []string{"example.com"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	certBytes, _, err := pki.SignCertificate(x509Crt, x509Crt, pk.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}
	return certBytes
}

func TestEncodeJKSKeystore(t *testing.T) {
	tests := map[string]struct {
		password               string
		rawKey, certPEM, caPEM []byte
		verify                 func(t *testing.T, out []byte, err error)
	}{
		"encode a JKS bundle for a PKCS1 key and certificate only": {
			password: "password",
			rawKey:   mustGeneratePrivateKey(t, cmapi.PKCS1),
			certPEM:  mustSelfSignCertificate(t, nil),
			verify: func(t *testing.T, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
					return
				}
				buf := bytes.NewBuffer(out)
				ks, err := jks.Decode(buf, []byte("password"))
				if err != nil {
					t.Errorf("error decoding keystore: %v", err)
					return
				}
				if ks["certificate"] == nil {
					t.Errorf("no certificate data found in keystore")
				}
				if ks["ca"] != nil {
					t.Errorf("unexpected ca data found in keystore")
				}
			},
		},
		"encode a JKS bundle for a PKCS8 key and certificate only": {
			password: "password",
			rawKey:   mustGeneratePrivateKey(t, cmapi.PKCS8),
			certPEM:  mustSelfSignCertificate(t, nil),
			verify: func(t *testing.T, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				buf := bytes.NewBuffer(out)
				ks, err := jks.Decode(buf, []byte("password"))
				if err != nil {
					t.Errorf("error decoding keystore: %v", err)
					return
				}
				if ks["certificate"] == nil {
					t.Errorf("no certificate data found in keystore")
				}
				if ks["ca"] != nil {
					t.Errorf("unexpected ca data found in keystore")
				}
			},
		},
		"encode a JKS bundle for a key, certificate and ca": {
			password: "password",
			rawKey:   mustGeneratePrivateKey(t, cmapi.PKCS8),
			certPEM:  mustSelfSignCertificate(t, nil),
			caPEM:    mustSelfSignCertificate(t, nil),
			verify: func(t *testing.T, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				buf := bytes.NewBuffer(out)
				ks, err := jks.Decode(buf, []byte("password"))
				if err != nil {
					t.Errorf("error decoding keystore: %v", err)
					return
				}
				if ks["certificate"] == nil {
					t.Errorf("no certificate data found in keystore")
				}
				if ks["ca"] == nil {
					t.Errorf("no ca data found in keystore")
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			out, err := encodeJKSKeystore([]byte(test.password), test.rawKey, test.certPEM, test.caPEM)
			test.verify(t, out, err)
		})
	}
}

func TestEncodePKCS12Keystore(t *testing.T) {
	tests := map[string]struct {
		password               string
		rawKey, certPEM, caPEM []byte
		verify                 func(t *testing.T, out []byte, err error)
	}{
		"encode a JKS bundle for a PKCS1 key and certificate only": {
			password: "password",
			rawKey:   mustGeneratePrivateKey(t, cmapi.PKCS1),
			certPEM:  mustSelfSignCertificate(t, nil),
			verify: func(t *testing.T, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				pk, cert, err := pkcs12.Decode(out, "password")
				if err != nil {
					t.Errorf("error decoding keystore: %v", err)
					return
				}
				if cert == nil {
					t.Errorf("no certificate data found in keystore")
				}
				if pk == nil {
					t.Errorf("no ca data found in keystore")
				}
			},
		},
		"encode a JKS bundle for a PKCS8 key and certificate only": {
			password: "password",
			rawKey:   mustGeneratePrivateKey(t, cmapi.PKCS8),
			certPEM:  mustSelfSignCertificate(t, nil),
			verify: func(t *testing.T, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				pk, cert, err := pkcs12.Decode(out, "password")
				if err != nil {
					t.Errorf("error decoding keystore: %v", err)
					return
				}
				if cert == nil {
					t.Errorf("no certificate data found in keystore")
				}
				if pk == nil {
					t.Errorf("no ca data found in keystore")
				}
			},
		},
		"encode a JKS bundle for a key, certificate and ca": {
			password: "password",
			rawKey:   mustGeneratePrivateKey(t, cmapi.PKCS8),
			certPEM:  mustSelfSignCertificate(t, nil),
			caPEM:    mustSelfSignCertificate(t, nil),
			verify: func(t *testing.T, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				// The pkcs12 package does not expose a way to decode the CA
				// data that has been written.
				// It will return an error when attempting to decode a file
				// with more than one 'certbag', so we just ensure the error
				// returned is the expected error and don't inspect the keystore
				// contents.
				_, _, err = pkcs12.Decode(out, "password")
				if err == nil || err.Error() != "pkcs12: expected exactly two safe bags in the PFX PDU" {
					t.Errorf("unexpected error string, exp=%q, got=%v", "pkcs12: expected exactly two safe bags in the PFX PDU", err)
					return
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			out, err := encodePKCS12Keystore(test.password, test.rawKey, test.certPEM, test.caPEM)
			test.verify(t, out, err)
		})
	}
}
