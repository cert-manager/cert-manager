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
		NotAfter:  time.Now().Add(defaultNotAfter),
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
