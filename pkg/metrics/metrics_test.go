package metrics

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestUpdateCertificateExpiry(t *testing.T) {
	const metadata = `
	# HELP certmanager_certificate_expiration_seconds The date after which the certificate expires. Expressed as a Unix Epoch Time.
	# TYPE certmanager_certificate_expiration_seconds gauge
`

	type testT struct {
		expected  string
		name      string
		namespace string
		cert      *x509.Certificate
	}
	tests := map[string]testT{
		"first": testT{
			name:      "something",
			namespace: "default",
			expected: `
	certmanager_certificate_expiration_seconds{name="something",namespace="default"} 2.208988804e+09
`,
			cert: &x509.Certificate{
				// fixed expiry time for testing
				NotAfter: time.Unix(2208988804, 0),
			},
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			updateX509Expiry(test.name, test.namespace, test.cert)

			if err := testutil.CollectAndCompare(
				CertificateExpiryTimeSeconds,
				strings.NewReader(metadata+test.expected),
				"certmanager_certificate_expiration_seconds",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}
		})
	}
}
