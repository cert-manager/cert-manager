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

func getReadyConditionStatus(crt *v1alpha1.Certificate) v1alpha1.ConditionStatus {
	for _, c := range crt.Status.Conditions {
		switch c.Type {
		case v1alpha1.CertificateConditionReady:
			return c.Status
		}
	}
	return v1alpha1.ConditionUnknown
}

func buildCertificate(name, namespace string, condition v1alpha1.ConditionStatus) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Status: v1alpha1.CertificateStatus{
			Conditions: []v1alpha1.CertificateCondition{
				{
					Type:   v1alpha1.CertificateConditionReady,
					Status: condition,
				},
			},
		},
	}
}

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

func TestUpdateCertificateReadyStatus(t *testing.T) {
	const metadata = `
	# HELP certmanager_certificate_ready_status The ready status of the certificate.
	# TYPE certmanager_certificate_ready_status gauge
`

	type testT struct {
		crt      *v1alpha1.Certificate
		expected string
	}
	tests := map[string]testT{
		"ready status true is updated correctly": {
			crt: buildCertificate("something", "default", v1alpha1.ConditionTrue),
			expected: `
	certmanager_certificate_ready_status{condition="False",name="something",namespace="default"} 0
	certmanager_certificate_ready_status{condition="True",name="something",namespace="default"} 1
	certmanager_certificate_ready_status{condition="Unknown",name="something",namespace="default"} 0
`,
		},
		"ready status false is updated correctly": {
			crt: buildCertificate("something", "default", v1alpha1.ConditionFalse),
			expected: `
	certmanager_certificate_ready_status{condition="False",name="something",namespace="default"} 1
	certmanager_certificate_ready_status{condition="True",name="something",namespace="default"} 0
	certmanager_certificate_ready_status{condition="Unknown",name="something",namespace="default"} 0
`,
		},
		"ready status unknown is updated correctly": {
			crt: buildCertificate("something", "default", v1alpha1.ConditionUnknown),
			expected: `
	certmanager_certificate_ready_status{condition="False",name="something",namespace="default"} 0
	certmanager_certificate_ready_status{condition="True",name="something",namespace="default"} 0
	certmanager_certificate_ready_status{condition="Unknown",name="something",namespace="default"} 1
`,
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			updateCertificateReadyStatus(test.crt, getReadyConditionStatus(test.crt))

			if err := testutil.CollectAndCompare(
				CertificateReadyStatus,
				strings.NewReader(metadata+test.expected),
				"certmanager_certificate_ready_status",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}
		})
	}
}

func TestCleanUp(t *testing.T) {
	const metadataExpiry = `
	# HELP certmanager_certificate_expiration_timestamp_seconds The date after which the certificate expires. Expressed as a Unix Epoch Time.
	# TYPE certmanager_certificate_expiration_timestamp_seconds gauge
`

	const metadataReady = `
	# HELP certmanager_certificate_ready_status The ready status of the certificate.
	# TYPE certmanager_certificate_ready_status gauge
`
	type testT struct {
		active         map[*v1alpha1.Certificate]*x509.Certificate
		inactive       map[*v1alpha1.Certificate]*x509.Certificate
		expectedExpiry string
		expectedReady  string
	}
	tests := map[string]testT{
		"inactive certificate metrics cleaned up while active certificate metrics kept": {
			active: map[*v1alpha1.Certificate]*x509.Certificate{
				buildCertificate("active", "default", v1alpha1.ConditionTrue): {
					// fixed expiry time for testing
					NotAfter: time.Unix(2208988804, 0),
				},
			},
			inactive: map[*v1alpha1.Certificate]*x509.Certificate{
				buildCertificate("inactive", "default", v1alpha1.ConditionTrue): {
					// fixed expiry time for testing
					NotAfter: time.Unix(2208988804, 0),
				},
			},
			expectedExpiry: `
	certmanager_certificate_expiration_timestamp_seconds{name="active",namespace="default"} 2.208988804e+09
`,
			expectedReady: `
	certmanager_certificate_ready_status{condition="False",name="active",namespace="default"} 0
	certmanager_certificate_ready_status{condition="True",name="active",namespace="default"} 1
	certmanager_certificate_ready_status{condition="Unknown",name="active",namespace="default"} 0
`,
		},
		"no metrics cleaned up when only active certificate metrics": {
			active: map[*v1alpha1.Certificate]*x509.Certificate{
				buildCertificate("active", "default", v1alpha1.ConditionTrue): {
					// fixed expiry time for testing
					NotAfter: time.Unix(2208988804, 0),
				},
				buildCertificate("also-active", "default", v1alpha1.ConditionTrue): {
					// fixed expiry time for testing
					NotAfter: time.Unix(2208988804, 0),
				},
			},
			inactive: map[*v1alpha1.Certificate]*x509.Certificate{},
			expectedExpiry: `
	certmanager_certificate_expiration_timestamp_seconds{name="active",namespace="default"} 2.208988804e+09
	certmanager_certificate_expiration_timestamp_seconds{name="also-active",namespace="default"} 2.208988804e+09
`,
			expectedReady: `
	certmanager_certificate_ready_status{condition="False",name="active",namespace="default"} 0
	certmanager_certificate_ready_status{condition="False",name="also-active",namespace="default"} 0
	certmanager_certificate_ready_status{condition="True",name="active",namespace="default"} 1
	certmanager_certificate_ready_status{condition="True",name="also-active",namespace="default"} 1
	certmanager_certificate_ready_status{condition="Unknown",name="active",namespace="default"} 0
	certmanager_certificate_ready_status{condition="Unknown",name="also-active",namespace="default"} 0
`,
		},
		"all metrics cleaned up when only inactive certificate metrics": {
			active: map[*v1alpha1.Certificate]*x509.Certificate{},
			inactive: map[*v1alpha1.Certificate]*x509.Certificate{
				buildCertificate("inactive", "default", v1alpha1.ConditionTrue): {
					// fixed expiry time for testing
					NotAfter: time.Unix(2208988804, 0),
				},
				buildCertificate("also-inactive", "default", v1alpha1.ConditionTrue): {
					// fixed expiry time for testing
					NotAfter: time.Unix(2208988804, 0),
				},
			},
			expectedExpiry: "",
			expectedReady:  "",
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			defer cleanUpCertificates(nil)

			var activeCrts []*v1alpha1.Certificate
			for crt, cert := range test.active {
				updateX509Expiry(crt, cert)
				updateCertificateReadyStatus(crt, getReadyConditionStatus(crt))
				activeCrts = append(activeCrts, crt)
			}
			for crt, cert := range test.inactive {
				updateCertificateReadyStatus(crt, getReadyConditionStatus(crt))
				updateX509Expiry(crt, cert)
			}

			cleanUpCertificates(activeCrts)

			if err := testutil.CollectAndCompare(
				CertificateExpiryTimeSeconds,
				strings.NewReader(metadataExpiry+test.expectedExpiry),
				"certmanager_certificate_expiration_timestamp_seconds",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}

			if err := testutil.CollectAndCompare(
				CertificateReadyStatus,
				strings.NewReader(metadataReady+test.expectedReady),
				"certmanager_certificate_ready_status",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}
		})
	}
}
