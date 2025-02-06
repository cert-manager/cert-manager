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
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"
	"time"

	testlogr "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/cmrand"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// Integration tests for the authority can be found in `test/integration/webhook/dynamic_authority_test.go`.

func testAuthority(t *testing.T, name string, cs *kubefake.Clientset) *DynamicAuthority {
	logger := testlogr.NewTestLoggerWithOptions(t, testlogr.Options{
		Verbosity: 3,
	})
	logger = logger.WithName(name)

	da := &DynamicAuthority{
		SecretNamespace: "test-namespace",
		SecretName:      "test-secret",
		CADuration:      365 * 24 * time.Hour,
		LeafDuration:    7 * 24 * time.Hour,

		newClient: func(_ *rest.Config) (kubernetes.Interface, error) {
			return cs, nil
		},
	}

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := da.Run(logf.NewContext(runCtx, logger)); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	return da
}

func TestDynamicAuthority(t *testing.T) {
	fake := kubefake.NewSimpleClientset()

	da := testAuthority(t, "authority", fake)

	// Test WatchRotation function
	output := make(chan struct{}, 1)
	da.WatchRotation(output)
	defer da.StopWatchingRotation(output)

	waitForRotationAndSign := func(testInitial bool) {
		privateKey, err := pki.GenerateECPrivateKey(521)
		if err != nil {
			t.Fatal(err)
		}

		template := &x509.Certificate{
			PublicKey: privateKey.Public(),
		}

		if testInitial {
			// If Sign works, we don't need to wait for rotation
			cert, err := da.Sign(template)
			if err == nil {
				assert.NotNil(t, cert)
				return
			}
		}

		select {
		case <-output:
			// Rotation detected
			cert, err := da.Sign(template)
			assert.NoError(t, err)
			assert.NotNil(t, cert)
		case <-time.After(5 * time.Second):
			t.Error("Timeout waiting for rotation")

			t.Log("Queue length:", len(output))
		}
	}

	waitForRotationAndSign(true)

	err := fake.CoreV1().Secrets(da.SecretNamespace).Delete(context.TODO(), da.SecretName, metav1.DeleteOptions{})
	assert.NoError(t, err)

	waitForRotationAndSign(false)

	secret, err := fake.CoreV1().Secrets(da.SecretNamespace).Get(context.TODO(), da.SecretName, metav1.GetOptions{})
	assert.NoError(t, err)

	secret.Data = map[string][]byte{
		"tls.crt": []byte("test"),
		"tls.key": []byte("test"),
	}
	_, err = fake.CoreV1().Secrets(da.SecretNamespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
	assert.NoError(t, err)

	waitForRotationAndSign(false)
}

func TestDynamicAuthorityMulti(t *testing.T) {
	fake := kubefake.NewSimpleClientset()

	authorities := make([]*DynamicAuthority, 0)
	for i := 0; i < 200; i++ {
		da := testAuthority(t, fmt.Sprintf("authority-%d", i), fake)
		authorities = append(authorities, da)
	}

	da := authorities[0]

	output := make(chan struct{}, 1)
	da.WatchRotation(output)
	defer da.StopWatchingRotation(output)

	waitForRotationAndSign := func() {
		privateKey, err := pki.GenerateECPrivateKey(521)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			PublicKey: privateKey.Public(),
		}

		// If Sign works, we don't need to wait for rotation
		cert, err := da.Sign(template)
		if err == nil {
			assert.NotNil(t, cert)
			return
		}

		select {
		case <-output:
			// Rotation detected
			cert, err := da.Sign(template)
			assert.NoError(t, err)
			assert.NotNil(t, cert)
		case <-time.After(5 * time.Second):
			t.Error("Timeout waiting for rotation")

			t.Log("Queue length:", len(output))
		}
	}

	waitForRotationAndSign()
}

func Test__caRequiresRegeneration(t *testing.T) {
	generateSecretData := func(mod func(*x509.Certificate)) map[string][]byte {
		// Generate a certificate and private key pair
		pk, err := pki.GenerateECPrivateKey(384)
		assert.NoError(t, err)

		pkBytes, err := pki.EncodePrivateKey(pk, cmapi.PKCS8)
		assert.NoError(t, err)

		serialNumber, err := cmrand.SerialNumber()
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
		name         string
		secret       *corev1.Secret
		expect       bool
		expectReason string
	}{
		{
			name: "Missing data in CA secret (nil data)",
			secret: &corev1.Secret{
				Data: nil,
			},
			expect:       true,
			expectReason: "Missing data in CA secret.",
		},
		{
			name: "Missing data in CA secret (missing ca.crt)",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"tls.key": []byte("private key"),
				},
			},
			expect:       true,
			expectReason: "Missing data in CA secret.",
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
			expect:       true,
			expectReason: "Different data in ca.crt and tls.crt.",
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
			expect:       true,
			expectReason: "Failed to parse data in CA secret.",
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
			expect:       true,
			expectReason: "Stored certificate is not marked as a CA.",
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
			expect:       true,
			expectReason: "CA certificate is nearing expiry.",
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
			expect:       true,
			expectReason: "CA certificate is nearing expiry.",
		},
		{
			name: "Ok",
			secret: &corev1.Secret{
				Data: generateSecretData(nil),
			},
			expect:       false,
			expectReason: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			required, reason := caRequiresRegeneration(test.secret)
			if required != test.expect {
				t.Errorf("Expected %v, but got %v", test.expect, required)
			}
			if reason != test.expectReason {
				t.Errorf("Expected %q, but got %q", test.expectReason, reason)
			}
		})
	}
}
