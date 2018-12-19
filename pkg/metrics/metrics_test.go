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
	# HELP certmanager_certificate_expiration_timestamp_seconds The date after which the certificate expires. Expressed as a Unix Epoch Time.
	# TYPE certmanager_certificate_expiration_timestamp_seconds gauge
`

	type testT struct {
		expected  string
		name      string
		namespace string
		cert      *x509.Certificate
	}
	tests := map[string]testT{
		"first": {
			name:      "something",
			namespace: "default",
			expected: `
	certmanager_certificate_expiration_timestamp_seconds{name="something",namespace="default"} 2.208988804e+09
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
				"certmanager_certificate_expiration_timestamp_seconds",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}
		})
	}
}

func TestUpdateCertificateIssuedLatency(t *testing.T) {
	const metadata = `
	# HELP certmanager_certificate_issued_latency_seconds The amount of time for a namespace secret to be issued after a certificate has been created.
	# TYPE certmanager_certificate_issued_latency_seconds histogram
`

	type testT struct {
		expected string
		latency  time.Duration
	}
	tests := map[string]testT{
		"latency is calculated correctly": {
			expected: `
	certmanager_certificate_issued_latency_seconds_bucket{le="30"} 0
	certmanager_certificate_issued_latency_seconds_bucket{le="60"} 1
	certmanager_certificate_issued_latency_seconds_bucket{le="120"} 1
	certmanager_certificate_issued_latency_seconds_bucket{le="180"} 1
	certmanager_certificate_issued_latency_seconds_bucket{le="240"} 1
	certmanager_certificate_issued_latency_seconds_bucket{le="300"} 1
	certmanager_certificate_issued_latency_seconds_bucket{le="+Inf"} 1
	certmanager_certificate_issued_latency_seconds_sum 60
	certmanager_certificate_issued_latency_seconds_count 1
`,
			latency: time.Duration(60000000000),
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			Default.UpdateCertificateIssuedLatency(test.latency)

			if err := testutil.CollectAndCompare(
				CertificateIssuedLatency,
				strings.NewReader(metadata+test.expected),
				"certmanager_certificate_issued_latency_seconds",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}
		})
	}
}
