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

	"github.com/go-logr/logr/testr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	"github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

const notBeforeMetadata = `
	# HELP certmanager_certificate_not_before_timestamp_seconds The timestamp before which the certificate is invalid, expressed as a Unix Epoch Time.
	# TYPE certmanager_certificate_not_before_timestamp_seconds gauge
`

const notAfterMetadata = `
	# HELP certmanager_certificate_not_after_timestamp_seconds The timestamp after which the certificate is invalid, expressed as a Unix Epoch Time.
	# TYPE certmanager_certificate_not_after_timestamp_seconds gauge
`

const expiryMetadata = `
	# HELP certmanager_certificate_expiration_timestamp_seconds The timestamp after which the certificate expires, expressed in Unix Epoch Time.
	# TYPE certmanager_certificate_expiration_timestamp_seconds gauge
`

const renewalTimeMetadata = `
	# HELP certmanager_certificate_renewal_timestamp_seconds The timestamp after which the certificate should be renewed, expressed in Unix Epoch Time.
	# TYPE certmanager_certificate_renewal_timestamp_seconds gauge
`

const readyMetadata = `
  # HELP certmanager_certificate_ready_status The ready status of the certificate.
  # TYPE certmanager_certificate_ready_status gauge
`

func TestCertificateMetrics(t *testing.T) {
	type testT struct {
		crt                                                                                     *cmapi.Certificate
		expectedNotBefore, expectedNotAfter, expectedExpiry, expectedReady, expectedRenewalTime string
	}
	tests := map[string]testT{
		"certificate with issuance and expiry time, and ready status": {
			crt: gen.Certificate("test-certificate",
				gen.SetCertificateNamespace("test-ns"),
				gen.SetCertificateIssuer(cmmeta.IssuerReference{
					Name:  "test-issuer",
					Kind:  "test-issuer-kind",
					Group: "test-issuer-group",
				}),
				gen.SetCertificateNotBefore(metav1.Time{
					Time: time.Unix(100, 0),
				}),
				gen.SetCertificateNotAfter(metav1.Time{
					Time: time.Unix(2208988804, 0),
				}),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
					Type:   cmapi.CertificateConditionReady,
					Status: cmmeta.ConditionTrue,
				}),
			),
			expectedNotAfter: `
		certmanager_certificate_not_after_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 2.208988804e+09
`,
			expectedNotBefore: `
		certmanager_certificate_not_before_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 100
`,
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

		"certificate with no expiry and no status should give an issuance and expiry of 0 and Unknown status": {
			crt: gen.Certificate("test-certificate",
				gen.SetCertificateNamespace("test-ns"),
				gen.SetCertificateIssuer(cmmeta.IssuerReference{
					Name:  "test-issuer",
					Kind:  "test-issuer-kind",
					Group: "test-issuer-group",
				}),
			),
			expectedNotAfter: `
		certmanager_certificate_not_after_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
`,
			expectedNotBefore: `
		certmanager_certificate_not_before_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 0
`,
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

		"certificate with issuance, expiry, and status False should give an expiry and False status": {
			crt: gen.Certificate("test-certificate",
				gen.SetCertificateNamespace("test-ns"),
				gen.SetCertificateIssuer(cmmeta.IssuerReference{
					Name:  "test-issuer",
					Kind:  "test-issuer-kind",
					Group: "test-issuer-group",
				}),
				gen.SetCertificateNotBefore(metav1.Time{
					Time: time.Unix(10, 0),
				}),
				gen.SetCertificateNotAfter(metav1.Time{
					Time: time.Unix(100, 0),
				}),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
					Type:   cmapi.CertificateConditionReady,
					Status: cmmeta.ConditionFalse,
				}),
			),
			expectedNotAfter: `
		certmanager_certificate_not_after_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 100
`,
			expectedNotBefore: `
		certmanager_certificate_not_before_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 10
`,
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
		"certificate with issuance, expiry, and status Unknown should give an expiry and Unknown status": {
			crt: gen.Certificate("test-certificate",
				gen.SetCertificateNamespace("test-ns"),
				gen.SetCertificateIssuer(cmmeta.IssuerReference{
					Name:  "test-issuer",
					Kind:  "test-issuer-kind",
					Group: "test-issuer-group",
				}),
				gen.SetCertificateNotBefore(metav1.Time{
					Time: time.Unix(10, 0),
				}),
				gen.SetCertificateNotAfter(metav1.Time{
					Time: time.Unix(99999, 0),
				}),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
					Type:   cmapi.CertificateConditionReady,
					Status: cmmeta.ConditionUnknown,
				}),
			),
			expectedNotAfter: `
		certmanager_certificate_not_after_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 99999
`,
			expectedNotBefore: `
		certmanager_certificate_not_before_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 10
`,
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
				gen.SetCertificateIssuer(cmmeta.IssuerReference{
					Name:  "test-issuer",
					Kind:  "test-issuer-kind",
					Group: "test-issuer-group",
				}),
				gen.SetCertificateNotBefore(metav1.Time{
					Time: time.Unix(10, 0),
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
			expectedNotAfter: `
		certmanager_certificate_not_after_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 2.208988804e+09
`,
			expectedNotBefore: `
		certmanager_certificate_not_before_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate",namespace="test-ns"} 10
`,
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
			m := New(testr.New(t), clock.RealClock{})

			fakeClient := fake.NewClientset()
			factory := externalversions.NewSharedInformerFactory(fakeClient, 0)
			certsInformer := factory.Certmanager().V1().Certificates()

			err := certsInformer.Informer().GetIndexer().Add(test.crt)
			assert.NoError(t, err)

			m.SetupCertificateCollector(certsInformer.Lister())

			if err := testutil.CollectAndCompare(m.certificateCollector,
				strings.NewReader(notAfterMetadata+test.expectedNotAfter),
				"certmanager_certificate_not_after_timestamp_seconds",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}

			if err := testutil.CollectAndCompare(m.certificateCollector,
				strings.NewReader(notBeforeMetadata+test.expectedNotBefore),
				"certmanager_certificate_not_before_timestamp_seconds",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}

			if err := testutil.CollectAndCompare(m.certificateCollector,
				strings.NewReader(expiryMetadata+test.expectedExpiry),
				"certmanager_certificate_expiration_timestamp_seconds",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}

			if err := testutil.CollectAndCompare(m.certificateCollector,
				strings.NewReader(renewalTimeMetadata+test.expectedRenewalTime),
				"certmanager_certificate_renewal_timestamp_seconds",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}

			if err := testutil.CollectAndCompare(m.certificateCollector,
				strings.NewReader(readyMetadata+test.expectedReady),
				"certmanager_certificate_ready_status",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}

			err = certsInformer.Informer().GetIndexer().Delete(test.crt)
			assert.NoError(t, err)
		})
	}
}

func TestCertificateCache(t *testing.T) {
	m := New(testr.New(t), clock.RealClock{})

	crt1 := gen.Certificate("crt1",
		gen.SetCertificateUID("uid-1"),
		gen.SetCertificateIssuer(cmmeta.IssuerReference{
			Name:  "test-issuer",
			Kind:  "test-issuer-kind",
			Group: "test-issuer-group",
		}),
		gen.SetCertificateNotBefore(metav1.Time{
			Time: time.Unix(99, 0),
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
		gen.SetCertificateIssuer(cmmeta.IssuerReference{
			Name:  "test-issuer",
			Kind:  "test-issuer-kind",
			Group: "test-issuer-group",
		}),
		gen.SetCertificateNotBefore(metav1.Time{
			Time: time.Unix(199, 0),
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
		gen.SetCertificateIssuer(cmmeta.IssuerReference{
			Name:  "test-issuer",
			Kind:  "test-issuer-kind",
			Group: "test-issuer-group",
		}),
		gen.SetCertificateNotBefore(metav1.Time{
			Time: time.Unix(299, 0),
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
		gen.SetCertificateDuration(&metav1.Duration{Duration: time.Second}),
	)

	fakeClient := fake.NewClientset()
	factory := externalversions.NewSharedInformerFactory(fakeClient, 0)
	certsInformer := factory.Certmanager().V1().Certificates()

	err := certsInformer.Informer().GetIndexer().Add(crt1)
	assert.NoError(t, err)
	err = certsInformer.Informer().GetIndexer().Add(crt2)
	assert.NoError(t, err)
	err = certsInformer.Informer().GetIndexer().Add(crt3)
	assert.NoError(t, err)

	m.SetupCertificateCollector(certsInformer.Lister())

	// Check all three metrics exist
	if err := testutil.CollectAndCompare(m.certificateCollector,
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

	if err := testutil.CollectAndCompare(m.certificateCollector,
		strings.NewReader(notAfterMetadata+`
        certmanager_certificate_not_after_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt1",namespace="default-unit-test-ns"} 100
        certmanager_certificate_not_after_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt2",namespace="default-unit-test-ns"} 200
        certmanager_certificate_not_after_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt3",namespace="default-unit-test-ns"} 300
`),
		"certmanager_certificate_not_after_timestamp_seconds",
	); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}

	if err := testutil.CollectAndCompare(m.certificateCollector,
		strings.NewReader(notBeforeMetadata+`
        certmanager_certificate_not_before_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt1",namespace="default-unit-test-ns"} 99
        certmanager_certificate_not_before_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt2",namespace="default-unit-test-ns"} 199
        certmanager_certificate_not_before_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt3",namespace="default-unit-test-ns"} 299
`),
		"certmanager_certificate_not_before_timestamp_seconds",
	); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}

	if err := testutil.CollectAndCompare(m.certificateCollector,
		strings.NewReader(expiryMetadata+`
        certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt1",namespace="default-unit-test-ns"} 100
        certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt2",namespace="default-unit-test-ns"} 200
        certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt3",namespace="default-unit-test-ns"} 300
`),
		"certmanager_certificate_expiration_timestamp_seconds",
	); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}

	if err := testutil.CollectAndCompare(m.certificateCollector,
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
	err = certsInformer.Informer().GetIndexer().Delete(crt2)
	assert.NoError(t, err)

	if err := testutil.CollectAndCompare(m.certificateCollector,
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

	if err := testutil.CollectAndCompare(m.certificateCollector,
		strings.NewReader(expiryMetadata+`
	        certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt1",namespace="default-unit-test-ns"} 100
	        certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt3",namespace="default-unit-test-ns"} 300
	`),
		"certmanager_certificate_expiration_timestamp_seconds",
	); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}

	if err := testutil.CollectAndCompare(m.certificateCollector,
		strings.NewReader(notAfterMetadata+`
	        certmanager_certificate_not_after_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt1",namespace="default-unit-test-ns"} 100
	        certmanager_certificate_not_after_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt3",namespace="default-unit-test-ns"} 300
	`),
		"certmanager_certificate_not_after_timestamp_seconds",
	); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}

	if err := testutil.CollectAndCompare(m.certificateCollector,
		strings.NewReader(notBeforeMetadata+`
	        certmanager_certificate_not_before_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt1",namespace="default-unit-test-ns"} 99
	        certmanager_certificate_not_before_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="crt3",namespace="default-unit-test-ns"} 299
	`),
		"certmanager_certificate_not_before_timestamp_seconds",
	); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}

	// Remove all Certificates (even is already removed) and observe no Certificates
	err = certsInformer.Informer().GetIndexer().Delete(crt1)
	assert.NoError(t, err)
	err = certsInformer.Informer().GetIndexer().Delete(crt2)
	assert.NoError(t, err)
	err = certsInformer.Informer().GetIndexer().Delete(crt3)
	assert.NoError(t, err)

	if testutil.CollectAndCount(m.certificateCollector, "certmanager_certificate_ready_status") != 0 {
		t.Errorf("unexpected collecting result")
	}
	if testutil.CollectAndCount(m.certificateCollector, "certmanager_certificate_expiration_timestamp_seconds") != 0 {
		t.Errorf("unexpected collecting result")
	}
	if testutil.CollectAndCount(m.certificateCollector, "certmanager_certificate_not_after_timestamp_seconds") != 0 {
		t.Errorf("unexpected collecting result")
	}
	if testutil.CollectAndCount(m.certificateCollector, "certmanager_certificate_not_before_timestamp_seconds") != 0 {
		t.Errorf("unexpected collecting result")
	}
}
