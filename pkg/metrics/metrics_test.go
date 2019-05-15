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

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUpdateCertificateExpiry(t *testing.T) {
	const metadata = `
	# HELP certmanager_certificate_expiration_timestamp_seconds The date after which the certificate expires. Expressed as a Unix Epoch Time.
	# TYPE certmanager_certificate_expiration_timestamp_seconds gauge
`
	type testT struct {
		crt      *v1alpha1.Certificate
		cert     *x509.Certificate
		expected string
	}
	tests := map[string]testT{
		"first": {
			crt: &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "something",
					Namespace: "default",
				},
			},
			cert: &x509.Certificate{
				// fixed expiry time for testing
				NotAfter: time.Unix(2208988804, 0),
			},
			expected: `
	certmanager_certificate_expiration_timestamp_seconds{name="something",namespace="default"} 2.208988804e+09
`,
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			defer cleanUpCertificates(nil)

			updateX509Expiry(test.crt, test.cert)

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

func TestCleanUp(t *testing.T) {
	const metadata = `
	# HELP certmanager_certificate_expiration_timestamp_seconds The date after which the certificate expires. Expressed as a Unix Epoch Time.
	# TYPE certmanager_certificate_expiration_timestamp_seconds gauge
`
	type testT struct {
		active   map[*v1alpha1.Certificate]*x509.Certificate
		inactive map[*v1alpha1.Certificate]*x509.Certificate
		expected string
	}
	tests := map[string]testT{
		"active and inactive": {
			active: map[*v1alpha1.Certificate]*x509.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "something",
						Namespace: "default",
					},
				}: {
					// fixed expiry time for testing
					NotAfter: time.Unix(2208988804, 0),
				},
			},
			inactive: map[*v1alpha1.Certificate]*x509.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "something-else",
						Namespace: "default",
					},
				}: {
					// fixed expiry time for testing
					NotAfter: time.Unix(2208988804, 0),
				},
			},
			expected: `
	certmanager_certificate_expiration_timestamp_seconds{name="something",namespace="default"} 2.208988804e+09
`,
		},
		"only active": {
			active: map[*v1alpha1.Certificate]*x509.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "something",
						Namespace: "default",
					},
				}: {
					// fixed expiry time for testing
					NotAfter: time.Unix(2208988804, 0),
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "something-else",
						Namespace: "default",
					},
				}: {
					// fixed expiry time for testing
					NotAfter: time.Unix(2208988804, 0),
				},
			},
			inactive: map[*v1alpha1.Certificate]*x509.Certificate{},
			expected: `
	certmanager_certificate_expiration_timestamp_seconds{name="something",namespace="default"} 2.208988804e+09
	certmanager_certificate_expiration_timestamp_seconds{name="something-else",namespace="default"} 2.208988804e+09
`,
		},
		"only inactive": {
			active: map[*v1alpha1.Certificate]*x509.Certificate{},
			inactive: map[*v1alpha1.Certificate]*x509.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "something",
						Namespace: "default",
					},
				}: {
					// fixed expiry time for testing
					NotAfter: time.Unix(2208988804, 0),
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "something-else",
						Namespace: "default",
					},
				}: {
					// fixed expiry time for testing
					NotAfter: time.Unix(2208988804, 0),
				},
			},
			expected: "",
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			defer cleanUpCertificates(nil)

			var activeCrts []*v1alpha1.Certificate
			for crt, cert := range test.active {
				updateX509Expiry(crt, cert)
				activeCrts = append(activeCrts, crt)
			}
			for crt, cert := range test.inactive {
				updateX509Expiry(crt, cert)
			}

			cleanUpCertificates(activeCrts)

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
