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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

func generatePrivateKeyBytes(keyAlgo cmapi.PrivateKeyAlgorithm, keySize int) ([]byte, error) {
	cert := buildCertificateWithKeyParams(keyAlgo, keySize)
	privateKey, err := GeneratePrivateKeyForCertificate(cert)
	if err != nil {
		return nil, err
	}

	return EncodePrivateKey(privateKey, cert.Spec.PrivateKey.Encoding)
}

func generatePKCS8PrivateKey(keyAlgo cmapi.PrivateKeyAlgorithm, keySize int) ([]byte, error) {
	privateKey, err := GeneratePrivateKeyForCertificate(buildCertificateWithKeyParams(keyAlgo, keySize))
	if err != nil {
		return nil, err
	}
	return EncodePKCS8PrivateKey(privateKey)
}

type testBundle struct {
	cert *x509.Certificate
	pem  []byte
	pk   crypto.PrivateKey
}

func mustCreateBundle(t *testing.T, issuer *testBundle, name string) *testBundle {
	pk, err := GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             pk.Public(),
		IsCA:                  true,
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	var (
		issuerKey  crypto.PrivateKey
		issuerCert *x509.Certificate
	)

	if issuer == nil {
		// Selfsigned (no issuer)
		issuerKey = pk
		issuerCert = template
	} else {
		issuerKey = issuer.pk
		issuerCert = issuer.cert
	}

	certpem, cert, err := SignCertificate(template, issuerCert, pk.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	return &testBundle{pem: certpem, cert: cert, pk: pk}
}

func TestParseCertificateChain(t *testing.T) {
	root := mustCreateBundle(t, nil, "root")
	int1 := mustCreateBundle(t, root, "int-1")
	int2 := mustCreateBundle(t, int1, "int-2")
	leaf := mustCreateBundle(t, int2, "leaf")
	random := mustCreateBundle(t, nil, "random")

	joinPEM := func(first []byte, rest ...[]byte) []byte {
		for _, b := range rest {
			first = append(first, b...)
		}
		return first
	}

	tests := map[string]struct {
		inputBundle  []byte
		expPEMBundle *PEMBundle
		expErr       bool
	}{
		"if single certificate passed, return single certificate": {
			inputBundle:  root.pem,
			expPEMBundle: &PEMBundle{ChainPEM: root.pem},
			expErr:       false,
		},
		"if two certificate chain passed in order, should return single ca and certificate": {
			inputBundle:  joinPEM(int1.pem, root.pem),
			expPEMBundle: &PEMBundle{ChainPEM: int1.pem, CAPEM: root.pem},
			expErr:       false,
		},
		"if two certificate chain passed out of order, should return single ca and certificate": {
			inputBundle:  joinPEM(root.pem, int1.pem),
			expPEMBundle: &PEMBundle{ChainPEM: int1.pem, CAPEM: root.pem},
			expErr:       false,
		},
		"if 3 certificate chain passed out of order, should return single ca and chain in order": {
			inputBundle:  joinPEM(root.pem, int2.pem, int1.pem),
			expPEMBundle: &PEMBundle{ChainPEM: joinPEM(int2.pem, int1.pem), CAPEM: root.pem},
			expErr:       false,
		},
		"empty entries should be ignored, and return ca and certificate": {
			inputBundle:  joinPEM(root.pem, int2.pem, []byte("\n#foo\n  \n"), int1.pem),
			expPEMBundle: &PEMBundle{ChainPEM: joinPEM(int2.pem, int1.pem), CAPEM: root.pem},
			expErr:       false,
		},
		"if 4 certificate chain passed in order, should return single ca and chain in order": {
			inputBundle:  joinPEM(leaf.pem, int1.pem, int2.pem, root.pem),
			expPEMBundle: &PEMBundle{ChainPEM: joinPEM(leaf.pem, int2.pem, int1.pem), CAPEM: root.pem},
			expErr:       false,
		},
		"if 4 certificate chain passed out of order, should return single ca and chain in order": {
			inputBundle:  joinPEM(root.pem, int1.pem, leaf.pem, int2.pem),
			expPEMBundle: &PEMBundle{ChainPEM: joinPEM(leaf.pem, int2.pem, int1.pem), CAPEM: root.pem},
			expErr:       false,
		},
		"if 3 certificate chain but has break in the chain, should return error": {
			inputBundle:  joinPEM(root.pem, int1.pem, leaf.pem),
			expPEMBundle: nil,
			expErr:       true,
		},
		"if 4 certificate chain but also random certificate, should return error": {
			inputBundle:  joinPEM(root.pem, int1.pem, leaf.pem, int2.pem, random.pem),
			expPEMBundle: nil,
			expErr:       true,
		},
		"if 6 certificate chain but some are duplicates, duplicates should be removed and return single ca with chain": {
			inputBundle:  joinPEM(int2.pem, int1.pem, root.pem, leaf.pem, int1.pem, root.pem),
			expPEMBundle: &PEMBundle{ChainPEM: joinPEM(leaf.pem, int2.pem, int1.pem), CAPEM: root.pem},
			expErr:       false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			bundle, err := ParseCertificateChainPEM(test.inputBundle)
			if (err != nil) != test.expErr {
				t.Errorf("unexpected error, exp=%t got=%v",
					test.expErr, err)
			}

			if !reflect.DeepEqual(bundle, test.expPEMBundle) {
				t.Errorf("unexpected pem bundle, exp=%+s got=%+s",
					test.expPEMBundle, bundle)
			}
		})
	}
}

func TestDecodePrivateKeyBytes(t *testing.T) {
	type testT struct {
		name         string
		keyBytes     []byte
		keyAlgo      cmapi.PrivateKeyAlgorithm
		expectErr    bool
		expectErrStr string
	}

	rsaKeyBytes, err := generatePrivateKeyBytes(cmapi.RSAKeyAlgorithm, MinRSAKeySize)
	if err != nil {
		t.Errorf("error generating key bytes: %s", err)
		return
	}

	pkcs8RsaKeyBytes, err := generatePKCS8PrivateKey(cmapi.RSAKeyAlgorithm, MinRSAKeySize)
	if err != nil {
		t.Errorf("error generating key bytes: %s", err)
		return
	}

	ecdsaKeyBytes, err := generatePrivateKeyBytes(cmapi.ECDSAKeyAlgorithm, 256)
	if err != nil {
		t.Errorf("error generating key bytes: %s", err)
		return
	}

	pkcs8EcdsaKeyBytes, err := generatePKCS8PrivateKey(cmapi.ECDSAKeyAlgorithm, 256)
	if err != nil {
		t.Errorf("error generating key bytes: %s", err)
		return
	}

	block := &pem.Block{Type: "BLAH BLAH BLAH", Bytes: []byte("blahblahblah")}
	blahKeyBytes := pem.EncodeToMemory(block)

	privateKeyBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("blahblahblah")}
	blahPrivateKeyBytes := pem.EncodeToMemory(privateKeyBlock)

	invalidKeyBytes := []byte("blah-blah-invalid")

	tests := []testT{
		{
			name:      "decode pem encoded rsa private key bytes",
			keyBytes:  rsaKeyBytes,
			keyAlgo:   cmapi.RSAKeyAlgorithm,
			expectErr: false,
		},
		{
			name:      "decode pkcs#8 encoded rsa private key bytes",
			keyBytes:  pkcs8RsaKeyBytes,
			keyAlgo:   cmapi.RSAKeyAlgorithm,
			expectErr: false,
		},
		{
			name:      "decode pem encoded ecdsa private key bytes",
			keyBytes:  ecdsaKeyBytes,
			keyAlgo:   cmapi.ECDSAKeyAlgorithm,
			expectErr: false,
		},
		{
			name:      "decode pkcs#8 encoded ecdsa private key bytes",
			keyBytes:  pkcs8EcdsaKeyBytes,
			keyAlgo:   cmapi.ECDSAKeyAlgorithm,
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

				if test.keyAlgo == cmapi.RSAKeyAlgorithm {
					_, ok := privateKey.(*rsa.PrivateKey)
					if !ok {
						t.Errorf("expected rsa private key, but got %T", privateKey)
						return
					}
				}

				if test.keyAlgo == cmapi.ECDSAKeyAlgorithm {
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
