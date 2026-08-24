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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func generatePrivateKeyBytes(keyAlgo v1.PrivateKeyAlgorithm, keySize int) ([]byte, error) {
	cert := buildCertificateWithKeyParams(keyAlgo, keySize)
	privateKey, err := GeneratePrivateKeyForCertificate(cert)
	if err != nil {
		return nil, err
	}

	return EncodePrivateKey(privateKey, cert.Spec.PrivateKey.Encoding)
}

func generatePKCS8PrivateKey(keyAlgo v1.PrivateKeyAlgorithm, keySize int) ([]byte, error) {
	privateKey, err := GeneratePrivateKeyForCertificate(buildCertificateWithKeyParams(keyAlgo, keySize))
	if err != nil {
		return nil, err
	}
	return EncodePKCS8PrivateKey(privateKey)
}

func TestDecodeX509CertificateSetBytes(t *testing.T) {
	certBytes := mustCreateBundle(t, nil, "test").pem

	keyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("dummy")})

	// A bundle containing a valid certificate followed by a non-certificate
	// PEM block, e.g. a combined cert+key file.
	certAndKeyBytes := append(append([]byte{}, certBytes...), keyBytes...)

	_, err := DecodeX509CertificateSetBytes(certAndKeyBytes)
	if err == nil {
		t.Fatal("expected an error decoding a bundle containing a non-certificate PEM block, got none")
	}

	expectErrStr := `expected a "CERTIFICATE" block, found "RSA PRIVATE KEY"`
	if !strings.Contains(err.Error(), expectErrStr) {
		t.Errorf("expected err string to match: '%s', got: '%s'", expectErrStr, err.Error())
	}

	certs, err := DecodeX509CertificateSetBytes(certBytes)
	if err != nil {
		t.Fatalf("unexpected error decoding a valid certificate: %s", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
}

func TestDecodeX509CertificateRequestBytes(t *testing.T) {
	pk, err := GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}

	csrDER, err := EncodeCSR(&x509.CertificateRequest{Subject: pkix.Name{CommonName: "test"}}, pk)
	if err != nil {
		t.Fatal(err)
	}
	csrBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	csr, err := DecodeX509CertificateRequestBytes(csrBytes)
	if err != nil {
		t.Fatalf("unexpected error decoding a valid CSR: %s", err)
	}
	if csr.Subject.CommonName != "test" {
		t.Errorf("expected common name %q, got %q", "test", csr.Subject.CommonName)
	}

	// A PEM block that isn't labelled as a certificate request, e.g. a
	// certificate mistakenly passed as spec.request.
	nonCSRBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("dummy")})

	_, err = DecodeX509CertificateRequestBytes(nonCSRBytes)
	if err == nil {
		t.Fatal("expected an error decoding a non-CSR PEM block, got none")
	}

	expectErrStr := `expected a "CERTIFICATE REQUEST" block, found "CERTIFICATE"`
	if !strings.Contains(err.Error(), expectErrStr) {
		t.Errorf("expected err string to match: '%s', got: '%s'", expectErrStr, err.Error())
	}
}

func TestDecodePrivateKeyBytes(t *testing.T) {
	type testT struct {
		name         string
		keyBytes     []byte
		keyAlgo      v1.PrivateKeyAlgorithm
		expectErr    bool
		expectErrStr string
	}

	rsaKeyBytes, err := generatePrivateKeyBytes(v1.RSAKeyAlgorithm, MinRSAKeySize)
	if err != nil {
		t.Errorf("error generating key bytes: %s", err)
		return
	}

	pkcs8RsaKeyBytes, err := generatePKCS8PrivateKey(v1.RSAKeyAlgorithm, MinRSAKeySize)
	if err != nil {
		t.Errorf("error generating key bytes: %s", err)
		return
	}

	ecdsaKeyBytes, err := generatePrivateKeyBytes(v1.ECDSAKeyAlgorithm, 256)
	if err != nil {
		t.Errorf("error generating key bytes: %s", err)
		return
	}

	pkcs8EcdsaKeyBytes, err := generatePKCS8PrivateKey(v1.ECDSAKeyAlgorithm, 256)
	if err != nil {
		t.Errorf("error generating key bytes: %s", err)
		return
	}

	block := &pem.Block{Type: "BLAHBLAHBLAH", Bytes: []byte("blahblahblah")}
	blahKeyBytes := pem.EncodeToMemory(block)

	privateKeyBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("blahblahblah")}
	blahPrivateKeyBytes := pem.EncodeToMemory(privateKeyBlock)

	invalidKeyBytes := []byte("blah-blah-invalid")

	tests := []testT{
		{
			name:      "decode pem encoded rsa private key bytes",
			keyBytes:  rsaKeyBytes,
			keyAlgo:   v1.RSAKeyAlgorithm,
			expectErr: false,
		},
		{
			name:      "decode pkcs#8 encoded rsa private key bytes",
			keyBytes:  pkcs8RsaKeyBytes,
			keyAlgo:   v1.RSAKeyAlgorithm,
			expectErr: false,
		},
		{
			name:      "decode pem encoded ecdsa private key bytes",
			keyBytes:  ecdsaKeyBytes,
			keyAlgo:   v1.ECDSAKeyAlgorithm,
			expectErr: false,
		},
		{
			name:      "decode pkcs#8 encoded ecdsa private key bytes",
			keyBytes:  pkcs8EcdsaKeyBytes,
			keyAlgo:   v1.ECDSAKeyAlgorithm,
			expectErr: false,
		},
		{
			name:         "fail to decode unknown pem encoded key bytes",
			keyBytes:     blahKeyBytes,
			expectErr:    true,
			expectErrStr: "unknown private key type",
		},
		{
			name:         "fail to decode unknown pkcs#8 encoded key bytes",
			keyBytes:     blahPrivateKeyBytes,
			expectErr:    true,
			expectErrStr: "error parsing pkcs#8 private key: asn1: structure error:",
		},
		{
			name:         "fail to decode unknown not pem encoded key bytes",
			keyBytes:     invalidKeyBytes,
			expectErr:    true,
			expectErrStr: "error decoding private key PEM block",
		},
	}

	testFn := func(test testT) func(*testing.T) {
		return func(t *testing.T) {
			privateKey, err := DecodePrivateKeyBytes(test.keyBytes)
			if test.expectErr {
				if err == nil {
					t.Error("expected err, but got no error")
					return
				}

				if !strings.Contains(err.Error(), test.expectErrStr) {
					t.Errorf("expected err string to match: '%s', got: '%s'", test.expectErrStr, err.Error())
					return
				}
			}

			if !test.expectErr {
				if err != nil {
					t.Errorf("expected no err, but got '%q'", err)
					return
				}

				if test.keyAlgo == v1.RSAKeyAlgorithm {
					_, ok := privateKey.(*rsa.PrivateKey)
					if !ok {
						t.Errorf("expected rsa private key, but got %T", privateKey)
						return
					}
				}

				if test.keyAlgo == v1.ECDSAKeyAlgorithm {
					_, ok := privateKey.(*ecdsa.PrivateKey)
					if !ok {
						t.Errorf("expected ecdsa private key, but got %T", privateKey)
						return
					}
				}
			}
		}
	}

	for _, test := range tests {
		t.Run(test.name, testFn(test))
	}
}
