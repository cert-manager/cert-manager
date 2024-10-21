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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/cmrand"
)

func buildCertificateWithKeyParams(keyAlgo v1.PrivateKeyAlgorithm, keySize int) *v1.Certificate {
	return &v1.Certificate{
		Spec: v1.CertificateSpec{
			CommonName: "test",
			DNSNames:   []string{"test.test"},
			PrivateKey: &v1.CertificatePrivateKey{
				Algorithm: keyAlgo,
				Size:      keySize,
			},
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
		keyAlgo      v1.PrivateKeyAlgorithm
		keySize      int
		expectErr    bool
		expectErrStr string
	}

	tests := []testT{
		{
			name:         "rsa key with weak keysize (< 2048)",
			keyAlgo:      v1.RSAKeyAlgorithm,
			keySize:      1024,
			expectErr:    true,
			expectErrStr: "weak rsa key size specified",
		},
		{
			name:         "rsa key with too big keysize (> 8192)",
			keyAlgo:      v1.RSAKeyAlgorithm,
			keySize:      8196,
			expectErr:    true,
			expectErrStr: "rsa key size specified too big",
		},
		{
			name:         "ecdsa key with unsupported keysize",
			keyAlgo:      v1.ECDSAKeyAlgorithm,
			keySize:      100,
			expectErr:    true,
			expectErrStr: "unsupported ecdsa key size specified",
		},
		{
			name:         "unsupported key algo specified",
			keyAlgo:      v1.PrivateKeyAlgorithm("blahblah"),
			keySize:      256,
			expectErr:    true,
			expectErrStr: "unsupported private key algorithm specified",
		},
		{
			name:      "eddsa key with random keysize",
			keyAlgo:   v1.Ed25519KeyAlgorithm,
			keySize:   100,
			expectErr: false,
		},
		{
			name:      "rsa key with keysize 2048",
			keyAlgo:   v1.RSAKeyAlgorithm,
			keySize:   2048,
			expectErr: false,
		},
		{
			name:      "rsa key with keysize 4096",
			keyAlgo:   v1.RSAKeyAlgorithm,
			keySize:   4096,
			expectErr: false,
		},
		{
			name:      "ecdsa key with keysize 256",
			keyAlgo:   v1.ECDSAKeyAlgorithm,
			keySize:   256,
			expectErr: false,
		},
		{
			name:      "ecdsa key with keysize 384",
			keyAlgo:   v1.ECDSAKeyAlgorithm,
			keySize:   384,
			expectErr: false,
		},
		{
			name:      "ecdsa key with keysize 521",
			keyAlgo:   v1.ECDSAKeyAlgorithm,
			keySize:   521,
			expectErr: false,
		},
		{
			name:      "valid key size with key algorithm not specified",
			keyAlgo:   v1.PrivateKeyAlgorithm(""),
			keySize:   2048,
			expectErr: false,
		},
		{
			name:      "rsa with keysize not specified",
			keyAlgo:   v1.RSAKeyAlgorithm,
			expectErr: false,
		},
		{
			name:      "ecdsa with keysize not specified",
			keyAlgo:   v1.ECDSAKeyAlgorithm,
			expectErr: false,
		},
		{
			name:      "eddsa with keysize not specified",
			keyAlgo:   v1.Ed25519KeyAlgorithm,
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
						t.Error(err)
						return
					}

					if !curve.IsOnCurve(key.PublicKey.X, key.PublicKey.Y) {
						t.Error("expected key to be on specified curve")
						return
					}
				}

				if test.keyAlgo == "ed25519" {
					// For eddsa algorithm keysize is ignored
					_, ok := privateKey.(ed25519.PrivateKey)
					if !ok {
						t.Errorf("expected ed25519 private key, but got %T", privateKey)
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

	serialNumber, err := cmrand.SerialNumber()
	if err != nil {
		panic(fmt.Errorf("failed to generate serial number: %s", err.Error()))
	}

	template := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
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

	csr1, err := x509.CreateCertificateRequest(cmrand.Reader, template, privKey1)
	if err != nil {
		t.Errorf("error generating csr1: %v", err)
	}
	csr2, err := x509.CreateCertificateRequest(cmrand.Reader, template, privKey2)
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

func TestPrivateKeyEncodings(t *testing.T) {
	type testT struct {
		name         string
		key          []byte
		keyEncoding  v1.PrivateKeyEncoding
		expectErr    bool
		expectErrStr string
	}

	const privKey = `
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC0sETnD5CNh/VZ
K3F3snYlD4t39YL30s56SiNmAOftZEvPkDqMzZh11/DlUggR9kQh/SpIQr/Gxg3o
TVG22AnjJynxlw1ikMNUa/Emq2of+MrEpn9oBKl+qproA07UrcVYuMrcPd7qRAco
2gwByIAJ2uIBR6OUO8bjwUhXlZ4Ui8ZqVwZD5ja+IlmlHpH5UDgzE7U2L7PfCHWZ
wTc2rtlgj6U2qQrxTOmHsiwJ6O8wjoR84XUtzPCAYHuh8pEbRZwDA/pVjFpA9+7w
JqKShcykSn9EQdCEuEG2oYP22AZ++X8kL7hQiynDWopYXB134wHlz5f5arN7zpmo
lzWQj/SRAgMBAAECggEAPn3ANtGxQuHEvyRBSA6WwdaQe9qTgzaLZswBViP2Eqpf
ddgCB/SLSCZ5EDbAx8WOZtryJq+/N/YDlVY4bq5lLQS8guulG3PJuobijmc2evxG
1KBo7AbAwCgtDxUlzHSVDkxLDMTxNcB1YXGYOX2omr/y7lJihr/t15Nfe7spQx1H
p/lTZO01LMa2sau1K3UyUO7b/fHmfiTDru3Ulf7MvXfdRM0CcUkdVVCMsNUmuQrV
aXJOuWHxlnxEHvy//Kjio1Efq52QCg5v5mNrliV4S+Fn/4rKKg1yEuMHQXL1Db0V
VU6tsEAWhY2ynab2My0Hzyj++lxP4vCau7s2HZrEgQKBgQDaC4DbwmAFIB4t/wq4
tfFP6yWQ1PHdHiJWm0VBooiD9Tg69Ar2WlmyEKD1DoEo6hA3xgKYraV9CGoDsIuz
Hx5w/sCP0DdcR2COK5JcPwo6QjzCPWvqSKFU2YRH9CniBeNZ/y8bRY2Pxxf+UfZM
oxBnIgBR7fsZ5ahcIT/qXEzhuQKBgQDUJBgnxRSu9pawJqBdX1qvjwymNjX+3vNW
aHoROr/z1Qz58NHobM3exrePMtznKaE3i52wv9jmAxbmOvyTSkc0/6hsKVYI+uVm
ipQd62GRJeFUeXznBA0HpoEe9Kw3fCg0QInDEnhXQwdLXD2E0XFqfYEAY0UEX2ky
kbuFvs/1mQKBgHiDLx9HGUb773JAqi5Y8RzYvJSF/X/W7eesPeT+7jDw0blTtNNg
MH8ITc3jzGNOqtQIrtqv7u1iPyX259+CbZLKWqehz1dDZAxv7J7rgL2eanJ4/DIr
HnAFIOWb/6Ia2wOc1O5fzNQQmCRKLLVC0wgNdNvTiptPoXP6NJdVmHCRAoGAN9js
twOOJ2VpVCRHEW257P/Gv7cDzf4Zp4THpeOGhwVubho02HBUXjKIPl2QhBaUh4/s
yowm6J6ll6Stu4TRbCVlzFuxd5m9bJpM1feSbui/AkMdW5/YYkw2L9UPxWedGexn
mAAzyB0wPWmiFGYi6nrxzA1WLQmFIzf0WwhZrPkCgYAfxHLDdjSfDp2yV6suFFVw
wr/9z3Hed+XCQvl+SSWNB3x9ge4q3mXh+XmYkVL144MBO2+KCENZHJHZsHPKR9Dl
OfVRvbdkFnyPY03IcQPpOifT2W0ydTaP02xqqeZ1s9ZfyQWNECt+E6SQwGtgkC3n
O7WnDn8nuLFdW+NzzbIrTw==
-----END PRIVATE KEY-----`
	privateKeyBytes := []byte(privKey)

	tests := []testT{
		{
			name:        "rsa 2048 private key with empty key encoding",
			key:         privateKeyBytes,
			keyEncoding: v1.PKCS1,
			expectErr:   false,
		},
		{
			name:        "rsa 2048 private key with pkcs1 key encoding",
			key:         privateKeyBytes,
			keyEncoding: v1.PKCS1,
			expectErr:   false,
		},
		{
			name:        "rsa 2048 private key with pkcs8 key encoding",
			key:         privateKeyBytes,
			keyEncoding: v1.PKCS8,
			expectErr:   false,
		},
	}

	testFn := func(test testT) func(*testing.T) {
		return func(t *testing.T) {
			block, _ := pem.Decode(privateKeyBytes)
			decodedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
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
				actualEncoding := v1.PrivateKeyEncoding("")
				block, _ := pem.Decode(encodedKey)

				switch block.Type {
				case "PRIVATE KEY":
					actualEncoding = v1.PKCS8
				case "RSA PRIVATE KEY":
					actualEncoding = v1.PKCS1
				case "EC PRIVATE KEY":
					actualEncoding = v1.PKCS1
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

func TestPublicKeysEqualECDSA(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), cmrand.Reader)
	if err != nil {
		t.Fatalf("couldn't generate P256 key: %v", err)
	}

	// note the different curve type
	key2, err := ecdsa.GenerateKey(elliptic.P521(), cmrand.Reader)
	if err != nil {
		t.Fatalf("couldn't generate P521 key: %v", err)
	}

	pub1 := key1.Public().(*ecdsa.PublicKey)

	// (pub1.X, pub1.Y) isn't likely to be on the curve for key2, so pub2 will be
	// invalid after changing its X and Y below; still, pub2 is useful for
	// the test

	// this is not dissimilar to the standard library's test:
	// https://github.com/golang/go/blob/14a18b7d2538232c6cd6937297c421d5f6b7d92f/src/crypto/ecdsa/equal_test.go#L55-L64
	pub2 := key2.Public().(*ecdsa.PublicKey)
	pub2.X = pub1.X
	pub2.Y = pub1.Y

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
