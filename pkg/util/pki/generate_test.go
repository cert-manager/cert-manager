/*
Copyright 2019 The Jetstack cert-manager contributors.

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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func buildCertificateWithKeyParams(keyAlgo v1alpha1.KeyAlgorithm, keySize int) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		Spec: v1alpha1.CertificateSpec{
			CommonName:   "test",
			DNSNames:     []string{"test.test"},
			KeyAlgorithm: keyAlgo,
			KeySize:      keySize,
		},
	}
}

func ecCurveForKeySize(keySize int) (elliptic.Curve, error) {
	switch keySize {
	case 0, ECCurve256:
		return elliptic.P256(), nil
	case ECCurve384:
		return elliptic.P384(), nil
	case ECCurve521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unknown ecdsa key size specified: %d", keySize)
	}
}

func TestGeneratePrivateKeyForCertificate(t *testing.T) {
	type testT struct {
		name         string
		keyAlgo      v1alpha1.KeyAlgorithm
		keySize      int
		expectErr    bool
		expectErrStr string
	}

	tests := []testT{
		{
			name:         "rsa key with weak keysize (< 2048)",
			keyAlgo:      v1alpha1.RSAKeyAlgorithm,
			keySize:      1024,
			expectErr:    true,
			expectErrStr: "weak rsa key size specified",
		},
		{
			name:         "rsa key with too big keysize (> 8192)",
			keyAlgo:      v1alpha1.RSAKeyAlgorithm,
			keySize:      8196,
			expectErr:    true,
			expectErrStr: "rsa key size specified too big",
		},
		{
			name:         "ecdsa key with unsupported keysize",
			keyAlgo:      v1alpha1.ECDSAKeyAlgorithm,
			keySize:      100,
			expectErr:    true,
			expectErrStr: "unsupported ecdsa key size specified",
		},
		{
			name:         "unsupported key algo specified",
			keyAlgo:      v1alpha1.KeyAlgorithm("blahblah"),
			keySize:      256,
			expectErr:    true,
			expectErrStr: "unsupported private key algorithm specified",
		},
		{
			name:      "rsa key with keysize 2048",
			keyAlgo:   v1alpha1.RSAKeyAlgorithm,
			keySize:   2048,
			expectErr: false,
		},
		{
			name:      "rsa key with keysize 4096",
			keyAlgo:   v1alpha1.RSAKeyAlgorithm,
			keySize:   4096,
			expectErr: false,
		},
		{
			name:      "ecdsa key with keysize 256",
			keyAlgo:   v1alpha1.ECDSAKeyAlgorithm,
			keySize:   256,
			expectErr: false,
		},
		{
			name:      "ecdsa key with keysize 384",
			keyAlgo:   v1alpha1.ECDSAKeyAlgorithm,
			keySize:   384,
			expectErr: false,
		},
		{
			name:      "ecdsa key with keysize 521",
			keyAlgo:   v1alpha1.ECDSAKeyAlgorithm,
			keySize:   521,
			expectErr: false,
		},
		{
			name:      "valid key size with key algorithm not specified",
			keyAlgo:   v1alpha1.KeyAlgorithm(""),
			keySize:   2048,
			expectErr: false,
		},
		{
			name:      "rsa with keysize not specified",
			keyAlgo:   v1alpha1.RSAKeyAlgorithm,
			expectErr: false,
		},
		{
			name:      "ecdsa with keysize not specified",
			keyAlgo:   v1alpha1.ECDSAKeyAlgorithm,
			expectErr: false,
		},
	}

	testFn := func(test testT) func(*testing.T) {
		return func(t *testing.T) {
			privateKey, err := GeneratePrivateKeyForCertificate(buildCertificateWithKeyParams(test.keyAlgo, test.keySize))
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

				if test.keyAlgo == "rsa" {
					// For rsa algorithm, if keysize is not provided, the default of 2048 will be used
					expectedRsaKeySize := 2048
					if test.keySize != 0 {
						expectedRsaKeySize = test.keySize
					}

					key, ok := privateKey.(*rsa.PrivateKey)
					if !ok {
						t.Errorf("expected rsa private key, but got %T", privateKey)
						return
					}

					actualKeySize := key.N.BitLen()
					if expectedRsaKeySize != actualKeySize {
						t.Errorf("expected %d, but got %d", expectedRsaKeySize, actualKeySize)
						return
					}
				}

				if test.keyAlgo == "ecdsa" {
					// For ecdsa algorithm, if keysize is not provided, the default of 256 will be used
					expectedEcdsaKeySize := ECCurve256
					if test.keySize != 0 {
						expectedEcdsaKeySize = test.keySize
					}

					key, ok := privateKey.(*ecdsa.PrivateKey)
					if !ok {
						t.Errorf("expected ecdsa private key, but got %T", privateKey)
						return
					}

					actualKeySize := key.Curve.Params().BitSize
					if expectedEcdsaKeySize != actualKeySize {
						t.Errorf("expected %d but got %d", expectedEcdsaKeySize, actualKeySize)
						return
					}

					curve, err := ecCurveForKeySize(test.keySize)
					if err != nil {
						t.Errorf(err.Error())
						return
					}

					if !curve.IsOnCurve(key.PublicKey.X, key.PublicKey.Y) {
						t.Error("expected key to be on specified curve")
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

func signTestCert(key crypto.Signer) *x509.Certificate {
	commonName := "testingcert"

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(fmt.Errorf("failed to generate serial number: %s", err.Error()))
	}

	template := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		Subject: pkix.Name{
			Organization: []string{defaultOrganization},
			CommonName:   commonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(v1alpha1.DefaultCertificateDuration),
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	_, crt, err := SignCertificate(template, template, key.Public(), key)
	if err != nil {
		panic(fmt.Errorf("error signing test cert: %v", err))
	}

	return crt
}

func TestPublicKeyMatchesCertificate(t *testing.T) {
	privKey1, err := GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("error generating private key: %v", err)
	}
	privKey2, err := GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("error generating private key: %v", err)
	}

	testCert1 := signTestCert(privKey1)
	testCert2 := signTestCert(privKey2)

	matches, err := PublicKeyMatchesCertificate(privKey1.Public(), testCert1)
	if err != nil {
		t.Errorf("expected no error, but got: %v", err)
	}
	if !matches {
		t.Errorf("expected private key to match certificate, but it did not")
	}

	matches, err = PublicKeyMatchesCertificate(privKey1.Public(), testCert2)
	if err != nil {
		t.Errorf("expected no error, but got: %v", err)
	}
	if matches {
		t.Errorf("expected private key to not match certificate, but it did")
	}
}

func TestPublicKeyMatchesCertificateRequest(t *testing.T) {
	privKey1, err := GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("error generating private key: %v", err)
	}
	privKey2, err := GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("error generating private key: %v", err)
	}

	template := &x509.CertificateRequest{
		Version: 3,
		// SignatureAlgorithm: sigAlgo,
		Subject: pkix.Name{
			CommonName: "cn",
		},
	}

	csr1, err := x509.CreateCertificateRequest(rand.Reader, template, privKey1)
	if err != nil {
		t.Errorf("error generating csr1: %v", err)
	}
	csr2, err := x509.CreateCertificateRequest(rand.Reader, template, privKey2)
	if err != nil {
		t.Errorf("error generating csr2: %v", err)
	}

	parsedCSR1, err := x509.ParseCertificateRequest(csr1)
	if err != nil {
		t.Errorf("error parsing csr1: %v", err)
	}
	parsedCSR2, err := x509.ParseCertificateRequest(csr2)
	if err != nil {
		t.Errorf("error parsing csr2: %v", err)
	}

	matches, err := PublicKeyMatchesCSR(privKey1.Public(), parsedCSR1)
	if err != nil {
		t.Errorf("expected no error, but got: %v", err)
	}
	if !matches {
		t.Errorf("expected private key to match certificate, but it did not")
	}

	matches, err = PublicKeyMatchesCSR(privKey1.Public(), parsedCSR2)
	if err != nil {
		t.Errorf("expected no error, but got: %v", err)
	}
	if matches {
		t.Errorf("expected private key to not match certificate, but it did")
	}
}

func TestPrivateKeyEncodings(t *testing.T){
	type testT struct {
		name         string
		key			 []byte
		keyEncoding  v1alpha1.KeyEncoding
		expectErr    bool
		expectErrStr string
	}

	privateKey := []byte("-----BEGIN RSA PRIVATE KEY-----MIIEogIBAAKCAQEAtLBE5w+QjYf1WStxd7J2JQ+Ld/WC99LOekojZgDn7WRLz5A6jM2Yddfw5VIIEfZEIf0qSEK/xsYN6E1RttgJ4ycp8ZcNYpDDVGvxJqtqH/jKxKZ/aASpfqqa6ANO1K3FWLjK3D3e6kQHKNoMAciACdriAUejlDvG48FIV5WeFIvGalcGQ+Y2viJZpR6R+VA4MxO1Ni+z3wh1mcE3Nq7ZYI+lNqkK8Uzph7IsCejvMI6EfOF1LczwgGB7ofKRG0WcAwP6VYxaQPfu8CaikoXMpEp/REHQhLhBtqGD9tgGfvl/JC+4UIspw1qKWFwdd+MB5c+X+Wqze86ZqJc1kI/0kQIDAQABAoIBAD59wDbRsULhxL8kQUgOlsHWkHvak4M2i2bMAVYj9hKqX3XYAgf0i0gmeRA2wMfFjmba8iavvzf2A5VWOG6uZS0EvILrpRtzybqG4o5nNnr8RtSgaOwGwMAoLQ8VJcx0lQ5MSwzE8TXAdWFxmDl9qJq/8u5SYoa/7deTX3u7KUMdR6f5U2TtNSzGtrGrtSt1MlDu2/3x5n4kw67t1JX+zL133UTNAnFJHVVQjLDVJrkK1WlyTrlh8ZZ8RB78v/yo4qNRH6udkAoOb+Zja5YleEvhZ/+KyioNchLjB0Fy9Q29FVVOrbBAFoWNsp2m9jMtB88o/vpcT+Lwmru7Nh2axIECgYEA2guA28JgBSAeLf8KuLXxT+slkNTx3R4iVptFQaKIg/U4OvQK9lpZshCg9Q6BKOoQN8YCmK2lfQhqA7CLsx8ecP7Aj9A3XEdgjiuSXD8KOkI8wj1r6kihVNmER/Qp4gXjWf8vG0WNj8cX/lH2TKMQZyIAUe37GeWoXCE/6lxM4bkCgYEA1CQYJ8UUrvaWsCagXV9ar48MpjY1/t7zVmh6ETq/89UM+fDR6GzN3sa3jzLc5ymhN4udsL/Y5gMW5jr8k0pHNP+obClWCPrlZoqUHethkSXhVHl85wQNB6aBHvSsN3woNECJwxJ4V0MHS1w9hNFxan2BAGNFBF9pMpG7hb7P9ZkCgYB4gy8fRxlG++9yQKouWPEc2LyUhf1/1u3nrD3k/u4w8NG5U7TTYDB/CE3N48xjTqrUCK7ar+7tYj8l9uffgm2Sylqnoc9XQ2QMb+ye64C9nmpyePwyKx5wBSDlm/+iGtsDnNTuX8zUEJgkSiy1QtMIDXTb04qbT6Fz+jSXVZhwkQKBgDfY7LcDjidlaVQkRxFtuez/xr+3A83+GaeEx6XjhocFbm4aNNhwVF4yiD5dkIQWlIeP7MqMJuiepZekrbuE0WwlZcxbsXeZvWyaTNX3km7ovwJDHVuf2GJMNi/VD8VnnRnsZ5gAM8gdMD1pohRmIup68cwNVi0JhSM39FsIWaz5AoGAH8Ryw3Y0nw6dslerLhRVcMK//c9x3nflwkL5fkkljQd8fYHuKt5l4fl5mJFS9eODATtvighDWRyR2bBzykfQ5Tn1Ub23ZBZ8j2NNyHED6Ton09ltMnU2j9NsaqnmdbPWX8kFjRArfhOkkMBrYJAt5zu1pw5/J7ixXVvjc82yK08=-----END RSA PRIVATE KEY-----")

	tests := []testT{
		{
			name: "rsa 2048 private key with empty key encoding",
			key: privateKey,
			keyEncoding: v1alpha1.KeyEncoding(""),
			expectErr: false,
		},
		{
			name: "rsa 2048 private key with pkcs1 key encoding",
			key: privateKey,
			keyEncoding: v1alpha1.PKCS1,
			expectErr: false,
		},
		{
			name: "rsa 2048 private key with pkcs8 key encoding",
			key: privateKey,
			keyEncoding: v1alpha1.PKCS8,
			expectErr: false,
		},
	}

	testFn := func(test testT) func(*testing.T) {
		return func(t *testing.T) {
			decodedKey, err := DecodePrivateKeyBytes(test.key)
			encodedKey, err := EncodePrivateKey(decodedKey, test.keyEncoding)

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

				expectedEncoding := test.keyEncoding
				actualEncoding := ""
				block, _ := pem.Decode(encodedKey)

				switch block.Type {
				case "PRIVATE KEY":
					actualEncoding = v1alpha1.PKCS8
				case "RSA PRIVATE KEY":
					actualEncoding = v1alpha1.PKCS1
				case "EC PRIVATE KEY":
					actualEncoding = v1alpha1.PKCS1
				default: 
					err := "unknown key encoding for private key"
					t.Errorf("%s", err)
				}

				if expectedEncoding != actualEncoding {
					t.Errorf("expected %s, but got %s", expectedEncoding, actualEncoding)
					return
				}
			}
		}
	}
	
	for _, test := range tests {
		t.Run(test.name, testFn(test))
	}
}
