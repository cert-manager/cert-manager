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

package metrics

import (
	"strings"
	"testing"
	"time"

	logtesting "github.com/go-logr/logr/testing"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/clock"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

const expiryMetadata = `
	# HELP certmanager_certificate_expiration_timestamp_seconds The date after which the certificate expires. Expressed as a Unix Epoch Time.
	# TYPE certmanager_certificate_expiration_timestamp_seconds gauge
`

const renewalTimeMetadata = `
	# HELP certmanager_certificate_renewal_timestamp_seconds The number of seconds before expiration time the certificate should renew.
	# TYPE certmanager_certificate_renewal_timestamp_seconds gauge
`

const readyMetadata = `
  # HELP certmanager_certificate_ready_status The ready status of the certificate.
  # TYPE certmanager_certificate_ready_status gauge
`

func TestCertificateMetrics(t *testing.T) {
	type testT struct {
		crt                                                *cmapi.Certificate
		expectedExpiry, expectedReady, expectedRenewalTime string
	}
	tests := map[string]testT{
		"certificate with expiry and ready status": {
			crt: gen.Certificate("test-certificate",
				gen.SetCertificateNamespace("test-ns"),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{
					Name:  "test-issuer",
					Kind:  "test-issuer-kind",
					Group: "test-issuer-group",
				}),
				gen.SetCertificateNotAfter(metav1.Time{
					Time: time.Unix(2208988804, 0),
				}),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
					Type:   cmapi.CertificateConditionReady,
					Status: cmmeta.ConditionTrue,
				}),
			),
			expectedExpiry: `
	certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 2.208988804e+09
`,
			expectedReady: `
        certmanager_certificate_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
        certmanager_certificate_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 1
        certmanager_certificate_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
`,
			expectedRenewalTime: `
		certmanager_certificate_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
`,
		},

		"certificate with no expiry and no status should give an expiry of 0 and Unknown status": {
			crt: gen.Certificate("test-certificate",
				gen.SetCertificateNamespace("test-ns"),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{
					Name:  "test-issuer",
					Kind:  "test-issuer-kind",
					Group: "test-issuer-group",
				}),
			),
			expectedExpiry: `
	certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
`,
			expectedReady: `
        certmanager_certificate_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
        certmanager_certificate_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
        certmanager_certificate_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 1
`,
			expectedRenewalTime: `
		certmanager_certificate_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
`,
		},

		"certificate with expiry and status False should give an expiry and False status": {
			crt: gen.Certificate("test-certificate",
				gen.SetCertificateNamespace("test-ns"),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{
					Name:  "test-issuer",
					Kind:  "test-issuer-kind",
					Group: "test-issuer-group",
				}),
				gen.SetCertificateNotAfter(metav1.Time{
					Time: time.Unix(100, 0),
				}),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
					Type:   cmapi.CertificateConditionReady,
					Status: cmmeta.ConditionFalse,
				}),
			),
			expectedExpiry: `
	certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 100
`,
			expectedReady: `
        certmanager_certificate_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 1
        certmanager_certificate_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
        certmanager_certificate_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
`,
			expectedRenewalTime: `
		certmanager_certificate_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
`,
		},
		"certificate with expiry and status Unknown should give an expiry and Unknown status": {
			crt: gen.Certificate("test-certificate",
				gen.SetCertificateNamespace("test-ns"),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{
					Name:  "test-issuer",
					Kind:  "test-issuer-kind",
					Group: "test-issuer-group",
				}),
				gen.SetCertificateNotAfter(metav1.Time{
					Time: time.Unix(99999, 0),
				}),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
					Type:   cmapi.CertificateConditionReady,
					Status: cmmeta.ConditionUnknown,
				}),
			),
			expectedExpiry: `
	certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 99999
`,
			expectedReady: `
        certmanager_certificate_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
        certmanager_certificate_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
        certmanager_certificate_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 1
`,
			expectedRenewalTime: `
		certmanager_certificate_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
`,
		},
		"certificate with expiry and ready status and renew before": {
			crt: gen.Certificate("test-certificate",
				gen.SetCertificateNamespace("test-ns"),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{
					Name:  "test-issuer",
					Kind:  "test-issuer-kind",
					Group: "test-issuer-group",
				}),
				gen.SetCertificateNotAfter(metav1.Time{
					Time: time.Unix(2208988804, 0),
				}),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
					Type:   cmapi.CertificateConditionReady,
					Status: cmmeta.ConditionTrue,
				}),
				gen.SetCertificateRenewalTime(metav1.Time{
					Time: time.Unix(2208988804, 0),
				}),
			),
			expectedExpiry: `
	certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 2.208988804e+09
`,
			expectedReady: `
        certmanager_certificate_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
        certmanager_certificate_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 1
        certmanager_certificate_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
`,
			expectedRenewalTime: `
		certmanager_certificate_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 2.208988804e+09
`,
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			m := New(logtesting.NewTestLogger(t), clock.RealClock{})
			m.UpdateCertificate(test.crt)

			if err := testutil.CollectAndCompare(m.certificateExpiryTimeSeconds,
				strings.NewReader(expiryMetadata+test.expectedExpiry),
				"certmanager_certificate_expiration_timestamp_seconds",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}

			if err := testutil.CollectAndCompare(m.certificateRenewalTimeSeconds,
				strings.NewReader(renewalTimeMetadata+test.expectedRenewalTime),
				"certmanager_certificate_renewal_timestamp_seconds",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}

			if err := testutil.CollectAndCompare(m.certificateReadyStatus,
				strings.NewReader(readyMetadata+test.expectedReady),
				"certmanager_certificate_ready_status",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}
		})
	}
}

func TestCertificateCache(t *testing.T) {
	m := New(logtesting.NewTestLogger(t), clock.RealClock{})

	crt1 := gen.Certificate("crt1",
		gen.SetCertificateUID("uid-1"),
		gen.SetCertificateIssuer(cmmeta.ObjectReference{
			Name:  "test-issuer",
			Kind:  "test-issuer-kind",
			Group: "test-issuer-group",
		}),
		gen.SetCertificateNotAfter(metav1.Time{
			Time: time.Unix(100, 0),
		}),
		gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionReady,
			Status: cmmeta.ConditionUnknown,
		}),
		gen.SetCertificateRenewalTime(metav1.Time{
			Time: time.Unix(100, 0),
		}))
	crt2 := gen.Certificate("crt2",
		gen.SetCertificateUID("uid-2"),
		gen.SetCertificateIssuer(cmmeta.ObjectReference{
			Name:  "test-issuer",
			Kind:  "test-issuer-kind",
			Group: "test-issuer-group",
		}),
		gen.SetCertificateNotAfter(metav1.Time{
			Time: time.Unix(200, 0),
		}),
		gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionReady,
			Status: cmmeta.ConditionTrue,
		}),
		gen.SetCertificateRenewalTime(metav1.Time{
			Time: time.Unix(200, 0),
		}),
	)
	crt3 := gen.Certificate("crt3",
		gen.SetCertificateUID("uid-3"),
		gen.SetCertificateIssuer(cmmeta.ObjectReference{
			Name:  "test-issuer",
			Kind:  "test-issuer-kind",
			Group: "test-issuer-group",
		}),
		gen.SetCertificateNotAfter(metav1.Time{
			Time: time.Unix(300, 0),
		}),
		gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionReady,
			Status: cmmeta.ConditionFalse,
		}),
		gen.SetCertificateRenewalTime(metav1.Time{
			Time: time.Unix(300, 0),
		}),
	)

	// Observe all three Certificate metrics
	m.UpdateCertificate(crt1)
	m.UpdateCertificate(crt2)
	m.UpdateCertificate(crt3)

	// Check all three metrics exist
	if err := testutil.CollectAndCompare(m.certificateReadyStatus,
		strings.NewReader(readyMetadata+`
        certmanager_certificate_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt1",namespace="default-unit-test-ns"} 0
        certmanager_certificate_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt2",namespace="default-unit-test-ns"} 0
        certmanager_certificate_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt3",namespace="default-unit-test-ns"} 1
        certmanager_certificate_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt1",namespace="default-unit-test-ns"} 0
        certmanager_certificate_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt2",namespace="default-unit-test-ns"} 1
        certmanager_certificate_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt3",namespace="default-unit-test-ns"} 0
        certmanager_certificate_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt1",namespace="default-unit-test-ns"} 1
        certmanager_certificate_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt2",namespace="default-unit-test-ns"} 0
        certmanager_certificate_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt3",namespace="default-unit-test-ns"} 0
`),
		"certmanager_certificate_ready_status",
	); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
	if err := testutil.CollectAndCompare(m.certificateExpiryTimeSeconds,
		strings.NewReader(expiryMetadata+`
        certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt1",namespace="default-unit-test-ns"} 100
        certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt2",namespace="default-unit-test-ns"} 200
        certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt3",namespace="default-unit-test-ns"} 300
`),
		"certmanager_certificate_expiration_timestamp_seconds",
	); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}

	if err := testutil.CollectAndCompare(m.certificateRenewalTimeSeconds,
		strings.NewReader(renewalTimeMetadata+`
        certmanager_certificate_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt1",namespace="default-unit-test-ns"} 100
        certmanager_certificate_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt2",namespace="default-unit-test-ns"} 200
        certmanager_certificate_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt3",namespace="default-unit-test-ns"} 300
`),
		"certmanager_certificate_renewal_timestamp_seconds",
	); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}

	// Remove second certificate and check not exists
	m.RemoveCertificate(types.NamespacedName{
		Namespace: "default-unit-test-ns",
		Name:      "crt2",
	})
	if err := testutil.CollectAndCompare(m.certificateReadyStatus,
		strings.NewReader(readyMetadata+`
        certmanager_certificate_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt1",namespace="default-unit-test-ns"} 0
        certmanager_certificate_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt3",namespace="default-unit-test-ns"} 1
        certmanager_certificate_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt1",namespace="default-unit-test-ns"} 0
        certmanager_certificate_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt3",namespace="default-unit-test-ns"} 0
        certmanager_certificate_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt1",namespace="default-unit-test-ns"} 1
        certmanager_certificate_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt3",namespace="default-unit-test-ns"} 0
`),
		"certmanager_certificate_ready_status",
	); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
	if err := testutil.CollectAndCompare(m.certificateExpiryTimeSeconds,
		strings.NewReader(expiryMetadata+`
        certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt1",namespace="default-unit-test-ns"} 100
        certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt3",namespace="default-unit-test-ns"} 300
`),
		"certmanager_certificate_expiration_timestamp_seconds",
	); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}

	// Remove all Certificates (even is already removed) and observe no Certificates
	m.RemoveCertificate(types.NamespacedName{
		Namespace: "default-unit-test-ns",
		Name:      "crt1",
	})
	m.RemoveCertificate(types.NamespacedName{
		Namespace: "default-unit-test-ns",
		Name:      "crt2",
	})
	m.RemoveCertificate(types.NamespacedName{
		Namespace: "default-unit-test-ns",
		Name:      "crt3",
	})
	if testutil.CollectAndCount(m.certificateReadyStatus, "certmanager_certificate_ready_status") != 0 {
		t.Errorf("unexpected collecting result")
	}
	if testutil.CollectAndCount(m.certificateExpiryTimeSeconds, "certmanager_certificate_expiration_timestamp_seconds") != 0 {
		t.Errorf("unexpected collecting result")
	}
}
