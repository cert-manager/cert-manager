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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"
	"time"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func buildCertificateWithKeyParams(keyAlgo v1.PrivateKeyAlgorithm, keySize int) *v1.Certificate {
	return buildCertificateWithKeyAndSigParams(keyAlgo, keySize, "")
}

func buildCertificateWithKeyAndSigParams(keyAlgo v1.PrivateKeyAlgorithm, keySize int, sigAlg v1.SignatureAlgorithm) *v1.Certificate {
	return &v1.Certificate{
		Spec: v1.CertificateSpec{
			CommonName: "test",
			DNSNames:   []string{"test.test"},
			PrivateKey: &v1.CertificatePrivateKey{
				Algorithm: keyAlgo,
				Size:      keySize,
			},
			SignatureAlgorithm: sigAlg,
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

func signTestCert(key crypto.Signer) *x509.Certificate {
	commonName := "testingcert"

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		Subject: pkix.Name{
			Organization: []string{"cert-manager"},
			CommonName:   commonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(v1.DefaultCertificateDuration),
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
		Version: 0,
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

func TestPublicKeysEqualECDSA(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("couldn't generate P256 key: %v", err)
	}

	// note the different curve type
	key2, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("couldn't generate P521 key: %v", err)
	}

	pub1 := key1.Public().(*ecdsa.PublicKey)
	pub2 := key2.Public().(*ecdsa.PublicKey)

	// Keys are on different curves → must not be equal
	if pub1.Equal(pub2) {
		t.Fatalf("invalid test: got a match from curves which should differ:\npub1: %#v\npub2: %#v\n", pub1, pub2)
	}

	match, err := PublicKeysEqual(pub1, pub2)
	if err != nil {
		t.Fatalf("unexpected error from PublicKeysEqual: %v", err)
	}

	if match {
		t.Errorf("got an incorrect match from different curves:\npub1 type: %#v\npub2 type: %#v\n", pub1.Params().Name, pub2.Params().Name)
	}
}

const hardcodedTestKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAtaX7TB+WQ4yhTRLw6G0V8oLRaRzjJ1UiAh1Uw+K8SpgMehfm
WS6//y0iBwCfQWTC4Fw1sU99XA8yOIN+fMMdNcmPxvP7JKlUQRrM3RpXXD5eo+MZ
fJmc344Pn5f/aMoFvDq745YLTP3C5PJj1qcljch00FPORCCCFtdFkynzKoclZruW
cJpbFgt9mE/Qk2Xed8FZ+AESZmxAYVEhCv3JETpQfO3cW15+Hxug4eMQ6daAyYjT
+52QbENIXliKYCS+LrguQJsMNMveajoWcGMHbQBs+I2umlh0UDYRAZ3PbgO9GDfZ
tUoasBDM0SDjvtpiL+8UnbDlrwfZYgwGo/YixQIDAQABAoIBAQCIc0yYXEn2KBeq
3AWXswn/iAFiok6IZ00KpZndI98pcZo9xOJGL/YN64taEz+OUfCJtPqoXPvgQZIK
HczQT4kLtIOKghAv8/rUhRtLI9Rn+HoDRj8I+CN9UyutSPKVdtxkDwLA7R9EEINs
lCAnSJvPK7uEGtAhIQJXwhIDgEmnsWSKq3OTNRbKe4kF7bOAVsEj9KZjmHcWuhDV
LJ0x1+uWo18UFztHmQL/Vp0VJKYBo2tAql3LjHtGFI+uZ38X2HsAgIQSjVvXZyR1
FvZx0XymoF8zYJzV2yfzgF9Toot4SWlKsUuX3w2FYj8hnQbn02x0m7sZmhNY25Fd
ljZCWOFpAoGBAOloRL0kKAA71lR6zwV7M+Xxozzk3u2x+GdTRCeBtnzjMQGtLs5/
KsOROPNj2/wv+rH8FhAFiFKcwr4RrouVWxqCd6YwtAiRe92NfkuXPIDTq2G6K9ge
i5Z5yMImjeG1P4GvaQg9f1YF8oNO/EEtWihyN+VcLQHJFy714cMhurZDAoGBAMc7
JjRmjtybZj3VzPTp0c2emce1fGHMtcmFX+dauLmGNDXCo/cJs4XYKlp6vhuBY4PR
IcbqVFBshk2cCC6IRTsAIcPLi4rwqe8uRhtHbyXN1lmcNqJq/l9Q8xoQf7l/ik4r
ttrSb7/I2hyEm2xJFTTXqbpx3AQqQQbPwl3sFuZXAoGBAKpv6UH0VQFWsHuf8ewe
uxb+DCU7O0521t0cgHgY0BkCDZcbz0Iaui90rBGOqeTNZFLzsWihoZoxvkLsxnhG
5+/DtXs1tUFMexada8vm89deuZbzS3DVXTjUVTTw0kou/+DDJf9OaN14Gk6oLqup
YlyGiyqA1JypKrSv99t1ldHhAoGAQBFKWOF+IX0rpMjjLwMd/8R36Vv4Uq706ogk
bg6jhq2cjok4FxIck/cOr6f3CHtUWChhd0kVsgMkMULy8pvJv45sTT1gc16vFwZH
bzBKktqdipWMkDBd+qLaelBB8pIMFNVD6Rxw6Tiawz71iB38XtDXeOhyezhnTtxy
wadROeMCgYEAlsfw3Gk5zftMFsPsfvFREvq3em+UC0jP5FLcz+LzTk1mEn+1SXtB
lFP7bcMXkRBh4tlk0gDLHvnwIomA+/dRnEIGBPl5nvZNF1HybUWxXTa3dW9Jw9V/
3J9xMYH/v9uMSt0j5xhPcTrI6HYtrT5lZMZNOI5vbVo3D6KYLWtfgWA=
-----END RSA PRIVATE KEY-----
`

func TestPublicKeysEqualRSA(t *testing.T) {
	// parse a hardcoded key rather than generating since generating RSA keys
	// is absurdly slow:
	// BenchmarkGen-8                12         101415795 ns/op
	// BenchmarkParse-8           48930             24361 ns/op
	rawKey, err := DecodePrivateKeyBytes([]byte(hardcodedTestKey))
	if err != nil {
		t.Fatalf("couldn't parse RSA test key: %v", err)
	}

	key1 := rawKey.(*rsa.PrivateKey)

	pub1 := key1.Public().(*rsa.PublicKey)

	// changing E like this might mean the public key is invalid, but
	// it should still be fine for testing our comparison function
	pub2 := &rsa.PublicKey{}
	*pub2 = *pub1

	// 3 is valid because the exponent in hardcodedTestKey is 65535
	// if the test key changes, this could have to change.
	// note that there are relatively few exponents actually used in the real world
	// and as such this shouldn't just be a random value
	pub2.E = 3

	if pub1.Equal(pub2) {
		t.Fatalf("invalid test: got a match from keys which should differ:\npub1: %#v\npub2: %#v\n", pub1, pub2)
	}

	match, err := PublicKeysEqual(pub1, pub2)
	if err != nil {
		t.Fatalf("unexpected error from PublicKeysEqual: %v", err)
	}

	if match {
		t.Errorf("got an incorrect match from different RSA keys:\npub1: %#v\npub2: %#v\n", pub1, pub2)
	}
}
