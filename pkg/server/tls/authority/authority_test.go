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

package authority

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// Integration tests for the authority can be found in `test/integration/webhook/dynamic_authority_test.go`.

func Test__caRequiresRegeneration(t *testing.T) {
	generateSecretData := func(mod func(*x509.Certificate)) map[string][]byte {
		// Generate a certificate and private key pair
		pk, err := pki.GenerateECPrivateKey(384)
		assert.NoError(t, err)
		pkBytes, err := pki.EncodePrivateKey(pk, cmapi.PKCS8)
		assert.NoError(t, err)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		assert.NoError(t, err)
		cert := &x509.Certificate{
			Version:               3,
			BasicConstraintsValid: true,
			SerialNumber:          serialNumber,
			PublicKeyAlgorithm:    x509.ECDSA,
			Subject: pkix.Name{
				CommonName: "cert-manager-webhook-ca",
			},
			IsCA:      true,
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(5 * time.Minute),
			KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		}
		if mod != nil {
			mod(cert)
		}
		_, cert, err = pki.SignCertificate(cert, cert, pk.Public(), pk)
		assert.NoError(t, err)
		certBytes, err := pki.EncodeX509(cert)
		assert.NoError(t, err)

		return map[string][]byte{
			"tls.crt": certBytes,
			"ca.crt":  certBytes,
			"tls.key": pkBytes,
		}
	}

	tests := []struct {
		name   string
		secret *corev1.Secret
		expect bool
	}{
		{
			name: "Missing data in CA secret (nil data)",
			secret: &corev1.Secret{
				Data: nil,
			},
			expect: true,
		},
		{
			name: "Missing data in CA secret (missing ca.crt)",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"tls.key": []byte("private key"),
				},
			},
			expect: true,
		},
		{
			name: "Different data in ca.crt and tls.crt",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"tls.crt": []byte("data1"),
					"ca.crt":  []byte("data2"),
					"tls.key": []byte("secret"),
				},
			},
			expect: true,
		},
		{
			name: "Failed to parse data in CA secret",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"tls.crt": []byte("cert"),
					"ca.crt":  []byte("cert"),
					"tls.key": []byte("secret"),
				},
			},
			expect: true,
		},
		{
			name: "Stored certificate is not marked as a CA",
			secret: &corev1.Secret{
				Data: generateSecretData(
					func(cert *x509.Certificate) {
						cert.IsCA = false
					},
				),
			},
			expect: true,
		},
		{
			name: "Root CA certificate is JUST nearing expiry",
			secret: &corev1.Secret{
				Data: generateSecretData(
					func(cert *x509.Certificate) {
						cert.NotBefore = time.Now().Add(-2*time.Hour - 1*time.Minute)
						cert.NotAfter = cert.NotBefore.Add(3 * time.Hour)
					},
				),
			},
			expect: true,
		},
		{
			name: "Root CA certificate is ALMOST nearing expiry",
			secret: &corev1.Secret{
				Data: generateSecretData(
					func(cert *x509.Certificate) {
						cert.NotBefore = time.Now().Add(-2*time.Hour + 1*time.Minute)
						cert.NotAfter = cert.NotBefore.Add(3 * time.Hour)
					},
				),
			},
			expect: false,
		},
		{
			name: "Root CA certificate is expired",
			secret: &corev1.Secret{
				Data: generateSecretData(
					func(cert *x509.Certificate) {
						cert.NotBefore = time.Now().Add(-1 * time.Hour)
						cert.NotAfter = time.Now().Add(-1 * time.Minute)
					},
				),
			},
			expect: true,
		},
		{
			name: "Ok",
			secret: &corev1.Secret{
				Data: generateSecretData(nil),
			},
			expect: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			required := (&DynamicAuthority{}).caRequiresRegeneration(test.secret)
			if required != test.expect {
				t.Errorf("Expected %v, but got %v", test.expect, required)
			}
		})
	}
}
