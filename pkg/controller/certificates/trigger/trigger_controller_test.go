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

package trigger

import (
	"context"
	"fmt"
	"testing"
	"time"

	logtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	"github.com/cert-manager/cert-manager/internal/controller/certificates/policies"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func Test_controller_ProcessItem(t *testing.T) {
	fixedNow := metav1.NewTime(time.Now())
	fixedClock := fakeclock.NewFakeClock(fixedNow.Time)

	// We don't need to full bundle, just a simple CertificateRequest.
	createCertificateRequestOrPanic := func(crt *cmapi.Certificate) *cmapi.CertificateRequest {
		return testcrypto.MustCreateCryptoBundle(t, crt, fixedClock).CertificateRequest
	}

	tests := map[string]struct {
		// key that should be passed to ProcessItem. If not set, the
		// 'namespace/name' of the 'Certificate' field will be used. If neither
		// is set, the key will be "".
		key types.NamespacedName

		// Certificate to be synced for the test. If not set, the 'key' will be
		// passed to ProcessItem instead.
		existingCertificate        *cmapi.Certificate
		existingCertManagerObjects []runtime.Object
		existingKubeObjects        []runtime.Object

		mockDataForCertificateReturn    policies.Input
		mockDataForCertificateReturnErr error
		wantDataForCertificateCalled    bool

		mockShouldReissue       func(t *testing.T) policies.Func
		wantShouldReissueCalled bool

		// wantEvent, if set, is an 'event string' that is expected to be fired.
		// For example, "Normal Issuing Re-issuance forced by unit test case"
		// where 'Normal' is the event severity, 'Issuing' is the reason and the
		// remainder is the message.
		wantEvent string

		// wantConditions is the expected set of conditions on the Certificate
		// resource if an Update is made.
		// If nil, no update is expected.
		// If empty, an update to the empty set/nil is expected.
		wantConditions []cmapi.CertificateCondition

		// wantErr is the expected error text returned by the controller, if any.
		wantErr string
	}{
		"do nothing if an empty 'key' is used": {},
		"do nothing if an invalid 'key' is used": {
			key: types.NamespacedName{
				Namespace: "abc",
				Name:      "def/ghi",
			},
		},
		"do nothing if a key references a Certificate that does not exist": {
			key: types.NamespacedName{
				Namespace: "namespace",
				Name:      "name",
			},
		},
		"should do nothing if Certificate already has 'Issuing' condition": {
			existingCertificate: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateGeneration(42),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
					Type:               "Issuing",
					Status:             "True",
					ObservedGeneration: 3,
				}),
			),
		},
		"should call shouldReissue with the correct cert, secret and current CR": {
			existingCertificate: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateSecretName("secret-1"),
				gen.SetCertificateGeneration(42),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(2),
			),
			wantDataForCertificateCalled: true,
			mockDataForCertificateReturn: policies.Input{
				Secret: gen.Secret("secret-1", gen.SetSecretNamespace("testns")),
				CurrentRevisionRequest: gen.CertificateRequest("cr-1", gen.SetCertificateRequestNamespace("testns"),
					gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-1", "cert-1-uid")),
					gen.SetCertificateRequestAnnotations(map[string]string{"cert-manager.io/certificate-revision": "2"}),
				),
			},
			wantShouldReissueCalled: true,
			mockShouldReissue: func(t *testing.T) policies.Func {
				return func(gotInput policies.Input) (string, string, bool) {
					expectInput := policies.Input{
						Certificate: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
							gen.SetCertificateSecretName("secret-1"),
							gen.SetCertificateGeneration(42),
							gen.SetCertificateUID("cert-1-uid"),
							gen.SetCertificateRevision(2),
						),
						CurrentRevisionRequest: gen.CertificateRequest("cr-1", gen.SetCertificateRequestNamespace("testns"),
							gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-1", "cert-1-uid")),
							gen.SetCertificateRequestAnnotations(map[string]string{"cert-manager.io/certificate-revision": "2"}),
						),
						Secret: gen.Secret("secret-1", gen.SetSecretNamespace("testns")),
					}
					assert.Equal(t, expectInput, gotInput)
					return "", "", false
				}
			},
		},
		"should log error when dataForCertificate errors": {
			existingCertificate:             gen.Certificate("cert-1", gen.SetCertificateNamespace("testns")),
			wantDataForCertificateCalled:    true,
			mockDataForCertificateReturnErr: fmt.Errorf("dataForCertificate failed"),
			wantErr:                         "dataForCertificate failed",
		},
		"should set Issuing=True if shouldReissue tells us to reissue": {
			existingCertificate: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateGeneration(42),
			),
			wantDataForCertificateCalled: true,
			mockDataForCertificateReturn: policies.Input{},
			wantShouldReissueCalled:      true,
			mockShouldReissue: func(*testing.T) policies.Func {
				return func(policies.Input) (string, string, bool) {
					return "ForceTriggered", "Re-issuance forced by unit test case", true
				}
			},
			wantEvent: "Normal Issuing Re-issuance forced by unit test case",
			wantConditions: []cmapi.CertificateCondition{{
				Type:               "Issuing",
				Status:             "True",
				Reason:             "ForceTriggered",
				Message:            "Re-issuance forced by unit test case",
				LastTransitionTime: &fixedNow,
				ObservedGeneration: 42,
			}},
		},
		// The combinations of number of failed issuances and last
		// failed issuance time that do or do not result in re-issuance
		// are tested in Test_shouldBackoffReissuingOnFailure below
		"should not set Issuing=True when issuance failed once 59 minutes ago": {
			existingCertificate: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(fixedNow.Add(-59*time.Minute))),
				gen.SetCertificateIssuanceAttempts(ptr.To(1)),
			),
			wantDataForCertificateCalled: true,
			mockDataForCertificateReturn: policies.Input{
				NextRevisionRequest: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
					gen.SetCertificateUID("cert-1-uid"),
					gen.SetCertificateRevision(2),
					gen.SetCertificateDNSNames("example.com"),
				)),
			},
			wantShouldReissueCalled: false,
		},
		"should set Issuing=True when issuance failed once 59 minutes ago but cert and next CR are mismatched": {
			existingCertificate: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateGeneration(42),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example-that-was-updated-by-user.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(fixedNow.Add(-59*time.Minute))),
				gen.SetCertificateIssuanceAttempts(ptr.To(1)),
			),
			wantDataForCertificateCalled: true,
			mockDataForCertificateReturn: policies.Input{
				NextRevisionRequest: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
					gen.SetCertificateUID("cert-1-uid"),
					gen.SetCertificateRevision(2),
					gen.SetCertificateDNSNames("example.com"),
				)),
			},
			wantShouldReissueCalled: true,
			mockShouldReissue: func(*testing.T) policies.Func {
				return func(policies.Input) (string, string, bool) {
					return "ForceTriggered", "Re-issuance forced by unit test case", true
				}
			},
			wantEvent: "Normal Issuing Re-issuance forced by unit test case",
			wantConditions: []cmapi.CertificateCondition{{
				Type:               "Issuing",
				Status:             "True",
				Reason:             "ForceTriggered",
				Message:            "Re-issuance forced by unit test case",
				LastTransitionTime: &fixedNow,
				ObservedGeneration: 42,
			}},
		},
		"should set Issuing=True when issuance failed once 61 minutes ago and shouldReissue returns true": {
			existingCertificate: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateGeneration(42),
				gen.SetCertificateLastFailureTime(metav1.NewTime(fixedNow.Add(-61*time.Minute))),
				gen.SetCertificateIssuanceAttempts(ptr.To(1)),
				gen.SetCertificateIssuanceAttempts(ptr.To(1)),
			),
			wantDataForCertificateCalled: true,
			mockDataForCertificateReturn: policies.Input{},
			wantShouldReissueCalled:      true,
			mockShouldReissue: func(*testing.T) policies.Func {
				return func(policies.Input) (string, string, bool) {
					return "ForceTriggered", "Re-issuance forced by unit test case", true
				}
			},
			wantEvent: "Normal Issuing Re-issuance forced by unit test case",
			wantConditions: []cmapi.CertificateCondition{{
				Type:               "Issuing",
				Status:             "True",
				Reason:             "ForceTriggered",
				Message:            "Re-issuance forced by unit test case",
				LastTransitionTime: &fixedNow,
				ObservedGeneration: 42,
			}},
		},
		"should not set Issuing=True when other Ceritificates with the same secret name are found, the secret does not exist and the certificate is not the first": {
			existingCertificate: gen.Certificate("cert-2",
				gen.SetCertificateCreationTimestamp(metav1.NewTime(fixedNow.Add(1*time.Minute))),
				gen.SetCertificateNamespace("testns"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateSecretName("secret-1"),
			),
			existingCertManagerObjects: []runtime.Object{
				gen.Certificate("cert-1",
					gen.SetCertificateCreationTimestamp(fixedNow),
					gen.SetCertificateNamespace("testns"),
					gen.SetCertificateRevision(1),
					gen.SetCertificateDNSNames("example.com"),
					gen.SetCertificateSecretName("secret-1"),
				),
			},
			wantDataForCertificateCalled: false,
			wantShouldReissueCalled:      false,
		},
		"should set Issuing=True when other Ceritificates with the same secret name are found, the secret does not exist and the certificate is the first": {
			existingCertificate: gen.Certificate("cert-1",
				gen.SetCertificateCreationTimestamp(fixedNow),
				gen.SetCertificateNamespace("testns"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateSecretName("secret-1"),
			),
			existingCertManagerObjects: []runtime.Object{
				gen.Certificate("cert-2",
					gen.SetCertificateCreationTimestamp(metav1.NewTime(fixedNow.Add(1*time.Minute))),
					gen.SetCertificateNamespace("testns"),
					gen.SetCertificateRevision(1),
					gen.SetCertificateDNSNames("example.com"),
					gen.SetCertificateSecretName("secret-1"),
				),
			},
			wantDataForCertificateCalled: true,
			mockDataForCertificateReturn: policies.Input{},
			wantShouldReissueCalled:      true,
			mockShouldReissue: func(*testing.T) policies.Func {
				return func(policies.Input) (string, string, bool) {
					return "ForceTriggered", "Re-issuance forced by unit test case", true
				}
			},
			wantEvent: "Normal Issuing Re-issuance forced by unit test case",
			wantConditions: []cmapi.CertificateCondition{{
				Type:               "Issuing",
				Status:             "True",
				Reason:             "ForceTriggered",
				Message:            "Re-issuance forced by unit test case",
				LastTransitionTime: &fixedNow,
			}},
		},
		"should set Issuing=True when other Ceritificates with the same secret name are found, the secret does exist and the certificate is the owner": {
			existingCertificate: gen.Certificate("cert-2",
				gen.SetCertificateCreationTimestamp(metav1.NewTime(fixedNow.Add(1*time.Minute))),
				gen.SetCertificateNamespace("testns"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateSecretName("secret-1"),
			),
			existingCertManagerObjects: []runtime.Object{
				gen.Certificate("cert-1",
					gen.SetCertificateCreationTimestamp(fixedNow),
					gen.SetCertificateNamespace("testns"),
					gen.SetCertificateRevision(1),
					gen.SetCertificateDNSNames("example.com"),
					gen.SetCertificateSecretName("secret-1"),
				),
			},
			existingKubeObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "secret-1",
						Namespace: "testns",
						Annotations: map[string]string{
							cmapi.CertificateNameKey: "cert-2",
						},
					},
				},
			},
			wantDataForCertificateCalled: true,
			mockDataForCertificateReturn: policies.Input{},
			wantShouldReissueCalled:      true,
			mockShouldReissue: func(*testing.T) policies.Func {
				return func(policies.Input) (string, string, bool) {
					return "ForceTriggered", "Re-issuance forced by unit test case", true
				}
			},
			wantEvent: "Normal Issuing Re-issuance forced by unit test case",
			wantConditions: []cmapi.CertificateCondition{{
				Type:               "Issuing",
				Status:             "True",
				Reason:             "ForceTriggered",
				Message:            "Re-issuance forced by unit test case",
				LastTransitionTime: &fixedNow,
			}},
		},
		"should not set Issuing=True when other Ceritificates with the same secret name are found, the secret does exist and the certificate is first but not the owner": {
			existingCertificate: gen.Certificate("cert-1",
				gen.SetCertificateCreationTimestamp(fixedNow),
				gen.SetCertificateNamespace("testns"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateSecretName("secret-1"),
			),
			existingCertManagerObjects: []runtime.Object{
				gen.Certificate("cert-2",
					gen.SetCertificateCreationTimestamp(metav1.NewTime(fixedNow.Add(1*time.Minute))),
					gen.SetCertificateNamespace("testns"),
					gen.SetCertificateRevision(1),
					gen.SetCertificateDNSNames("example.com"),
					gen.SetCertificateSecretName("secret-1"),
				),
			},
			existingKubeObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "secret-1",
						Namespace: "testns",
						Annotations: map[string]string{
							cmapi.CertificateNameKey: "cert-2",
						},
					},
				},
			},
			wantDataForCertificateCalled: false,
			wantShouldReissueCalled:      false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			builder := &testpkg.Builder{
				T:     t,
				Clock: fixedClock,
			}
			if test.existingCertificate != nil {
				builder.CertManagerObjects = append(builder.CertManagerObjects, test.existingCertificate)
			}
			if test.existingCertManagerObjects != nil {
				builder.CertManagerObjects = append(builder.CertManagerObjects, test.existingCertManagerObjects...)
			}
			if test.existingKubeObjects != nil {
				builder.KubeObjects = append(builder.KubeObjects, test.existingKubeObjects...)
			}
			builder.Init()

			w := &controllerWrapper{}
			_, _, err := w.Register(builder.Context)
			if err != nil {
				t.Fatal(err)
			}

			gotShouldReissueCalled := false
			w.shouldReissue = func(i policies.Input) (string, string, bool) {
				gotShouldReissueCalled = true
				if test.mockShouldReissue == nil {
					t.Fatal("no mock set for shouldReissue, but shouldReissue has been called")
					return "", "", false
				}
				return test.mockShouldReissue(t)(i)
			}

			// TODO(mael): we should really remove the Certificate field from
			// DataForCertificate since the input certificate is always expected
			// to be the same as the output certificate.
			test.mockDataForCertificateReturn.Certificate = test.existingCertificate

			gotDataForCertificateCalled := false
			w.dataForCertificate = func(context.Context, *cmapi.Certificate) (policies.Input, error) {
				gotDataForCertificateCalled = true
				return test.mockDataForCertificateReturn, test.mockDataForCertificateReturnErr
			}

			if test.wantConditions != nil {
				if test.existingCertificate == nil {
					t.Fatal("cannot expect an Update operation if test.certificate is nil")
				}
				expectedCert := test.existingCertificate.DeepCopy()
				expectedCert.Status.Conditions = test.wantConditions
				builder.ExpectedActions = append(builder.ExpectedActions,
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						"status",
						test.existingCertificate.Namespace,
						expectedCert,
					)),
				)
			}
			if test.wantEvent != "" {
				builder.ExpectedEvents = []string{test.wantEvent}
			}

			builder.Start()
			defer builder.Stop()

			key := test.key
			if key == (types.NamespacedName{}) && test.existingCertificate != nil {
				key = types.NamespacedName{
					Name:      test.existingCertificate.Name,
					Namespace: test.existingCertificate.Namespace,
				}
			}

			gotErr := w.controller.ProcessItem(context.Background(), key)
			switch {
			case gotErr != nil:
				if test.wantErr != gotErr.Error() {
					t.Errorf("error text did not match, got=%s, exp=%s", gotErr.Error(), test.wantErr)
				}
			default:
				if test.wantErr != "" {
					t.Errorf("got no error but expected: %s", test.wantErr)
				}
			}

			assert.Equal(t, test.wantDataForCertificateCalled, gotDataForCertificateCalled, "dataForCertificate func call")
			assert.Equal(t, test.wantShouldReissueCalled, gotShouldReissueCalled, "shouldReissue func call")

			builder.CheckAndFinish()
		})
	}
}

func Test_shouldBackoffReissuingOnFailure(t *testing.T) {
	clock := fakeclock.NewFakeClock(time.Date(2020, 11, 20, 16, 05, 00, 0000, time.Local))

	// We don't need to full bundle, just a simple CertificateRequest.
	createCertificateRequestOrPanic := func(crt *cmapi.Certificate) *cmapi.CertificateRequest {
		return testcrypto.MustCreateCryptoBundle(t, crt, clock).CertificateRequest
	}

	tests := map[string]struct {
		givenCert   *cmapi.Certificate
		givenNextCR *cmapi.CertificateRequest
		wantBackoff bool
		wantDelay   time.Duration
	}{
		"no need to backoff from reissuing when the input request is nil": {
			givenCert:   gen.Certificate("test", gen.SetCertificateNamespace("testns")),
			wantBackoff: false,
		},
		"should not back off from reissuing when cert is not failing": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				// LastFailureTime is not set here.
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateRevision(1),
			)),
			wantBackoff: false,
		},
		"should back off from reissuing for 1 minute if there was 1 failed issuance 59 minutes ago": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now().Add(-59*time.Minute))),
				gen.SetCertificateIssuanceAttempts(ptr.To(1)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: true,
			wantDelay:   1 * time.Minute,
		},
		"should back off from reissuing for 1 hour if there was 1 failed issuance 0 minutes ago": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now())),
				gen.SetCertificateIssuanceAttempts(ptr.To(1)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: true,
			wantDelay:   1 * time.Hour,
		},
		"should not back off from reissuing if there was 1 failed issuance 61 minutes ago": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now().Add(-61*time.Minute))),
				gen.SetCertificateIssuanceAttempts(ptr.To(1)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: false,
		},
		"should back off from reissuing for 2 hours if there were 2 failed issuances, last one 0 minutes ago": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now())),
				gen.SetCertificateIssuanceAttempts(ptr.To(2)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: true,
			wantDelay:   2 * time.Hour,
		},
		"should not back off from reissuing if there were 2 failed issuances, last one 2h1min ago": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now().Add(-121*time.Minute))),
				gen.SetCertificateIssuanceAttempts(ptr.To(2)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: false,
		},
		"should back off from reissuing for 4 hours if there were 3 failed issuances, last one 0 minutes ago": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now())),
				gen.SetCertificateIssuanceAttempts(ptr.To(3)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: true,
			wantDelay:   4 * time.Hour,
		},
		"should not back off from reissuing if there were 3 failed issuances, last one 4h5min ago": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now().Add(-245*time.Minute))),
				gen.SetCertificateIssuanceAttempts(ptr.To(3)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: false,
		},
		"should back off from reissuing for 8 hours if there were 4 failed issuances, last one 0 minutes ago": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now())),
				gen.SetCertificateIssuanceAttempts(ptr.To(4)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: true,
			wantDelay:   8 * time.Hour,
		},
		"should not back off from reissuing if there were 4 failed issuances, last one 10h ago": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now().Add(-10*time.Hour))),
				gen.SetCertificateIssuanceAttempts(ptr.To(4)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: false,
		},
		"should back off from reissuing for 16 hours if there were 5 failed issuances, last one 0 minutes ago": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now())),
				gen.SetCertificateIssuanceAttempts(ptr.To(5)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: true,
			wantDelay:   16 * time.Hour,
		},
		"should not back off from reissuing if there were 5 failed issuances, last one 17h1min ago": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now().Add(-1021*time.Minute))),
				gen.SetCertificateIssuanceAttempts(ptr.To(5)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: false,
		},
		"should back off from reissuing for 32 hours if there were  6 failed issuances, last one 0 minutes ago": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now())),
				gen.SetCertificateIssuanceAttempts(ptr.To(6)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: true,
			wantDelay:   32 * time.Hour,
		},
		"should not back off from reissuing if there were  6 failed issuances, last one 32h ago": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now().Add(-32*time.Hour))),
				gen.SetCertificateIssuanceAttempts(ptr.To(6)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: false,
		},
		"should back off from reissuing for 32 hours if there were 100 failed issuances, last one 0 minutes ago": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now())),
				gen.SetCertificateIssuanceAttempts(ptr.To(100)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: true,
			wantDelay:   32 * time.Hour,
		},
		"should not back off from reissuing if there were 100 failed issuances, last one 32h ago": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now().Add(-32*time.Hour))),
				gen.SetCertificateIssuanceAttempts(ptr.To(100)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: false,
		},
		// This scenario will happen if an issuance failed for a version of cert-manager that does not implement exponential backoff
		"should back off from reissuing for 1 hour if there was a failed issuance, 0 minutes ago and issuance attempts is not set": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now())),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: true,
			wantDelay:   1 * time.Hour,
		},
		// This scenario will happen if an issuance failed for a version of cert-manager that does not implement exponential backoff
		"should back off from reissuing for 1 minute if there was a failed issuance 59 minutes ago and issuance attempts is not set": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now().Add(-59*time.Minute))),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: true,
			wantDelay:   1 * time.Minute,
		},
		// This scenario will happen if an issuance failed for a version of cert-manager that does not implement exponential backoff
		"should not back off from reissuing if there was a failed issuance 1 hour ago and issuance attempts is not set": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now().Add(-1*time.Hour))),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: false,
		},
		"should not back off from reissuing when the failure happened 0 minutes ago and cert and next CR are mismatched": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example-was-changed-by-user.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now())),
				gen.SetCertificateIssuanceAttempts(ptr.To(1)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: false,
		},
		"should not back off from reissuing when the failure happened 1 minutes ago and cert and next CR are mismatched": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example-was-updated-by-user.com"),
				gen.SetCertificateLastFailureTime(metav1.NewTime(clock.Now().Add(-1*time.Minute))),
				gen.SetCertificateIssuanceAttempts(ptr.To(1)),
			),
			givenNextCR: createCertificateRequestOrPanic(gen.Certificate("cert-1", gen.SetCertificateNamespace("testns"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
				gen.SetCertificateDNSNames("example.com"),
			)),
			wantBackoff: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotBackoff, gotDelay := shouldBackoffReissuingOnFailure(logtesting.NewTestLogger(t), clock, test.givenCert, test.givenNextCR)
			assert.Equal(t, test.wantBackoff, gotBackoff)
			assert.Equal(t, test.wantDelay, gotDelay)
		})

	}
}
