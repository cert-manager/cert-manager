/*
Copyright 2026 The cert-manager Authors.

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
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	cmmeta "github.com/cert-manager/cert-manager/internal/apis/meta"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

func TestDynamicAuthorityMetrics(t *testing.T) {
	fake := kubefake.NewClientset()
	// The metrics are global, so use a Secret name that no other test uses.
	da := testAuthorityForSecret(t, "authority", "metrics-test-secret", fake)

	caExpiry := caExpirationTimestampSeconds.WithLabelValues(da.SecretNamespace, da.SecretName)
	certExpiry := certificateExpirationTimestampSeconds.WithLabelValues(da.SecretNamespace, da.SecretName)
	successes := certificateSigningsTotal.WithLabelValues(da.SecretNamespace, da.SecretName, "success")
	failures := certificateSigningsTotal.WithLabelValues(da.SecretNamespace, da.SecretName, "failure")
	// The counters are global and not reset between test runs (e.g. with
	// -count), so compare against their initial values.
	initialSuccesses := testutil.ToFloat64(successes)
	initialFailures := testutil.ToFloat64(failures)

	storedCAExpiry := func() float64 {
		secret, err := fake.CoreV1().Secrets(da.SecretNamespace).Get(t.Context(), da.SecretName, metav1.GetOptions{})
		if err != nil {
			return -1
		}
		caCert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
		if err != nil {
			return -1
		}
		return float64(caCert.NotAfter.Unix())
	}

	// The CA metric reflects the generated CA once it has been loaded.
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(caExpiry) == storedCAExpiry()
	}, 5*time.Second, 10*time.Millisecond)

	// Signing a certificate records its expiry and counts the success. The CA
	// might not be loaded by the time the CA metric is observed above, so
	// retry until it is.
	pk, err := pki.GenerateECPrivateKey(256)
	require.NoError(t, err)
	var cert *x509.Certificate
	require.Eventually(t, func() bool {
		cert, err = da.Sign(&x509.Certificate{PublicKey: pk.Public()})
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)
	assert.InDelta(t, initialSuccesses+1, testutil.ToFloat64(successes), 0)
	assert.InDelta(t, initialFailures, testutil.ToFloat64(failures), 0)
	assert.InDelta(t, float64(cert.NotAfter.Unix()), testutil.ToFloat64(certExpiry), 0)

	// A failed signing is counted and leaves the expiry of the last signed
	// certificate untouched.
	_, err = da.Sign(&x509.Certificate{PublicKey: "not a public key"})
	require.Error(t, err)
	assert.InDelta(t, initialSuccesses+1, testutil.ToFloat64(successes), 0)
	assert.InDelta(t, initialFailures+1, testutil.ToFloat64(failures), 0)
	assert.InDelta(t, float64(cert.NotAfter.Unix()), testutil.ToFloat64(certExpiry), 0)

	// Replacing the CA updates the CA metric.
	newCANotAfter := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	secret, err := fake.CoreV1().Secrets(da.SecretNamespace).Get(t.Context(), da.SecretName, metav1.GetOptions{})
	require.NoError(t, err)
	secret.Data = generateCASecretData(t, newCANotAfter)
	_, err = fake.CoreV1().Secrets(da.SecretNamespace).Update(t.Context(), secret, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(caExpiry) == float64(newCANotAfter.Unix())
	}, 5*time.Second, 10*time.Millisecond)
}

func TestDynamicAuthorityMetricsCANotAvailable(t *testing.T) {
	// Run has not been called, so the CA is not available.
	da := &DynamicAuthority{
		SecretNamespace: "test-namespace",
		SecretName:      "metrics-not-available-test-secret",
	}

	_, err := da.Sign(&x509.Certificate{})
	require.ErrorIs(t, err, ErrCertificateNotAvailable)

	// Attempts made while the CA is not available are not counted as failures.
	assert.InDelta(t, 0, testutil.ToFloat64(certificateSigningsTotal.WithLabelValues(da.SecretNamespace, da.SecretName, "failure")), 0)
	assert.InDelta(t, 0, testutil.ToFloat64(certificateSigningsTotal.WithLabelValues(da.SecretNamespace, da.SecretName, "success")), 0)
}

func TestRegisterMetrics(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()

	require.NoError(t, RegisterMetrics(reg))
	// Registering the same metrics again is a no-op.
	require.NoError(t, RegisterMetrics(reg))

	for _, c := range collectors() {
		problems, err := testutil.CollectAndLint(c)
		require.NoError(t, err)
		assert.Empty(t, problems)
	}
}

func TestRegisterMetricsCollision(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()

	// A different collector exposing the same metric must not be mistaken for
	// the metrics of this package.
	require.NoError(t, reg.Register(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "certificate_signings_total",
			Help: "Total number of attempts to sign a dynamic serving certificate. Attempts made before the CA is available are not counted. " +
				"Labels: secret_namespace, secret_name (the Secret storing the signing CA), status (success/failure).",
		},
		[]string{"secret_namespace", "secret_name", "status"},
	)))

	require.ErrorAs(t, RegisterMetrics(reg), &prometheus.AlreadyRegisteredError{})
}

func generateCASecretData(t *testing.T, notAfter time.Time) map[string][]byte {
	pk, err := pki.GenerateECPrivateKey(256)
	require.NoError(t, err)
	pkBytes, err := pki.EncodePrivateKey(pk, cmapi.PKCS8)
	require.NoError(t, err)

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		PublicKeyAlgorithm:    x509.ECDSA,
		Subject: pkix.Name{
			CommonName: "test-common-name",
		},
		IsCA:      true,
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
	}
	_, cert, err := pki.SignCertificate(template, template, pk.Public(), pk)
	require.NoError(t, err)
	certBytes, err := pki.EncodeX509(cert)
	require.NoError(t, err)

	return map[string][]byte{
		corev1.TLSCertKey:       certBytes,
		corev1.TLSPrivateKeyKey: pkBytes,
		cmmeta.TLSCAKey:         certBytes,
	}
}
