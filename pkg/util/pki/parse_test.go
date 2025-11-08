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

func TestDecodeMLDSAPrivateKeyPEM(t *testing.T) {
	privKey := `-----BEGIN PRIVATE KEY-----
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
SpDPZVKIKQUPgHV2ESJlx7n/UvbLD1YJ
-----END PRIVATE KEY-----`
	_, err := DecodePrivateKeyBytes([]byte(privKey))
	if err != nil {
		t.Fatal(err)
	}
}
