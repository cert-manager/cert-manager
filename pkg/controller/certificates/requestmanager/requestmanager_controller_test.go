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

package requestmanager

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kr/pretty"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/component-base/featuregate"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func mustGenerateRSA(t *testing.T) []byte {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	d, err := pki.EncodePKCS8PrivateKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func relaxedCertificateRequestMatcher(l coretesting.Action, r coretesting.Action) error {
	objL := l.(coretesting.CreateAction).GetObject().(*cmapi.CertificateRequest).DeepCopy()
	objR := r.(coretesting.CreateAction).GetObject().(*cmapi.CertificateRequest).DeepCopy()
	objL.Spec.Request = nil
	objR.Spec.Request = nil
	if !reflect.DeepEqual(objL, objR) {
		return fmt.Errorf("unexpected difference between actions: %s", pretty.Diff(objL, objR))
	}
	return nil
}

func TestProcessItem(t *testing.T) {
	bundle1 := mustCreateCryptoBundle(t, &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "testns",
			Name:      "test",
			UID:       "test",
		},
		Spec: cmapi.CertificateSpec{CommonName: "test-bundle-1"}},
	)
	bundle2 := mustCreateCryptoBundle(t, &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "testns",
			Name:      "test",
			UID:       "test",
		},
		Spec: cmapi.CertificateSpec{CommonName: "test-bundle-2"}},
	)
	bundle3 := mustCreateCryptoBundle(t, &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "testns",
			Name:      "test",
			UID:       "test",
		},
		Spec: cmapi.CertificateSpec{CommonName: "test-bundle-3"}},
	)
	bundle4 := mustCreateCryptoBundle(t, &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "testns",
			Name:      strings.Repeat("a", 167) + "b" + strings.Repeat("c", 85),
			UID:       "test",
		},
		Spec: cmapi.CertificateSpec{CommonName: "test-bundle-4"}},
	)
	fixedNow := metav1.NewTime(time.Now())
	fixedClock := fakeclock.NewFakeClock(fixedNow.Time)
	failedCRConditionPreviousIssuance := cmapi.CertificateRequestCondition{
		Type:               cmapi.CertificateRequestConditionReady,
		Status:             cmmeta.ConditionFalse,
		Reason:             cmapi.CertificateRequestReasonFailed,
		LastTransitionTime: &metav1.Time{Time: fixedNow.Time.Add(-1 * time.Hour)},
	}
	failedCRConditionThisIssuance := cmapi.CertificateRequestCondition{
		Type:               cmapi.CertificateRequestConditionReady,
		Status:             cmmeta.ConditionFalse,
		Reason:             cmapi.CertificateRequestReasonFailed,
		LastTransitionTime: &metav1.Time{Time: fixedNow.Time.Add(1 * time.Minute)},
	}
	tests := map[string]struct {
		// key that should be passed to ProcessItem.
		// if not set, the 'namespace/name' of the 'Certificate' field will be used.
		// if neither is set, the key will be ""
		key types.NamespacedName

		// Featuregates to set for a particular test.
		featuresFlags map[featuregate.Feature]bool

		// Certificate to be synced for the test.
		// if not set, the 'key' will be passed to ProcessItem instead.
		certificate *cmapi.Certificate

		secrets []runtime.Object

		// Request, if set, will exist in the apiserver before the test is run.
		requests []runtime.Object

		expectedActions []testpkg.Action

		expectedEvents []string

		// err is the expected error text returned by the controller, if any.
		err string
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
		"do nothing if Certificate has 'Issuing' condition set to 'false'": {
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionFalse}),
			),
		},
		"do nothing if Certificate has no 'Issuing' condition": {
			certificate: bundle1.certificate,
		},
		"do nothing if status.nextPrivateKeySecretName is not set": {
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
			),
		},
		"do nothing if status.nextPrivateKeySecretName does not exist": {
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateNextPrivateKeySecretName("does-not-exist"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
			),
		},
		"do nothing if status.nextPrivateKeySecretName contains no data": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "exists-but-empty"},
				},
			},
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists-but-empty"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
			),
		},
		"do nothing if status.nextPrivateKeySecretName contains invalid data": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "exists-but-invalid"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: []byte("invalid")},
				},
			},
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists-but-invalid"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
			),
		},
		"create a CertificateRequest if none exists and StableCertificateRequestName disabled": {
			featuresFlags: map[featuregate.Feature]bool{
				feature.StableCertificateRequestName: false,
			},
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: bundle1.certificate.Namespace, Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: bundle1.privateKeyBytes},
				},
			},
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
			),
			expectedEvents: []string{`Normal Requested Created new CertificateRequest resource "test-notrandom"`},
			expectedActions: []testpkg.Action{
				testpkg.NewCustomMatch(coretesting.NewCreateAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns",
					gen.CertificateRequestFrom(bundle1.certificateRequest,
						gen.SetCertificateRequestName(""),
						gen.SetCertificateRequestGenerateName("test-"),
						gen.SetCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
							cmapi.CertificateRequestRevisionAnnotationKey:   "1",
						}),
					)), relaxedCertificateRequestMatcher),
			},
		},
		"create a CertificateRequest if none exists": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: bundle3.certificate.Namespace, Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: bundle3.privateKeyBytes},
				},
			},
			certificate: gen.CertificateFrom(bundle3.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
			),
			expectedEvents: []string{`Normal Requested Created new CertificateRequest resource "test-1"`},
			expectedActions: []testpkg.Action{
				testpkg.NewCustomMatch(coretesting.NewCreateAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns",
					gen.CertificateRequestFrom(bundle3.certificateRequest,
						gen.SetCertificateRequestName("test-1"),
						gen.SetCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
							cmapi.CertificateRequestRevisionAnnotationKey:   "1",
						}),
					)), relaxedCertificateRequestMatcher),
			},
		},
		"create a CertificateRequest if none exists (with long name)": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: bundle3.certificate.Namespace, Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: bundle3.privateKeyBytes},
				},
			},
			certificate: gen.CertificateFrom(bundle4.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
				gen.SetCertificateRevision(19),
			),
			expectedEvents: []string{
				fmt.Sprintf(`Normal Requested Created new CertificateRequest resource "%s"`, strings.Repeat("a", 167)+"b-d3f4fc40a686edfd404adf1d3fb1530653988c878e6c9c07b2e2fa4001a21269-20"),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewCustomMatch(coretesting.NewCreateAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns",
					gen.CertificateRequestFrom(bundle4.certificateRequest,
						gen.SetCertificateRequestName(strings.Repeat("a", 167)+"b-d3f4fc40a686edfd404adf1d3fb1530653988c878e6c9c07b2e2fa4001a21269-20"),
						gen.SetCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
							cmapi.CertificateRequestRevisionAnnotationKey:   "20",
						}),
					)), relaxedCertificateRequestMatcher),
			},
		},
		"create a CertificateRequest if none exists (with long name and very large revision)": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: bundle3.certificate.Namespace, Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: bundle3.privateKeyBytes},
				},
			},
			certificate: gen.CertificateFrom(bundle4.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
				gen.SetCertificateRevision(999999999),
			),
			expectedEvents: []string{
				fmt.Sprintf(`Normal Requested Created new CertificateRequest resource "%s"`, strings.Repeat("a", 167)+"b-d3f4fc40a686edfd404adf1d3fb1530653988c878e6c9c07b2e2fa4001a21269-1000000000"),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewCustomMatch(coretesting.NewCreateAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns",
					gen.CertificateRequestFrom(bundle4.certificateRequest,
						gen.SetCertificateRequestName(strings.Repeat("a", 167)+"b-d3f4fc40a686edfd404adf1d3fb1530653988c878e6c9c07b2e2fa4001a21269-1000000000"),
						gen.SetCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
							cmapi.CertificateRequestRevisionAnnotationKey:   "1000000000",
						}),
					)), relaxedCertificateRequestMatcher),
			},
		},
		"delete the owned CertificateRequest and create a new one if existing one does not have the annotation": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: mustGenerateRSA(t)},
				},
			},
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("random-value"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "",
					}),
				),
			},
			expectedEvents: []string{`Normal Requested Created new CertificateRequest resource "test-1"`},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns", "random-value")),
				testpkg.NewCustomMatch(coretesting.NewCreateAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns",
					gen.CertificateRequestFrom(bundle1.certificateRequest,
						gen.SetCertificateRequestName("test-1"),
						gen.SetCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
							cmapi.CertificateRequestRevisionAnnotationKey:   "1",
						}),
					)), relaxedCertificateRequestMatcher),
			},
		},
		"delete the owned CertificateRequest and create a new one if existing one contains invalid annotation": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: mustGenerateRSA(t)},
				},
			},
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("random-value"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "invalid",
					}),
				),
			},
			expectedEvents: []string{`Normal Requested Created new CertificateRequest resource "test-1"`},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns", "random-value")),
				testpkg.NewCustomMatch(coretesting.NewCreateAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns",
					gen.CertificateRequestFrom(bundle1.certificateRequest,
						gen.SetCertificateRequestName("test-1"),
						gen.SetCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
							cmapi.CertificateRequestRevisionAnnotationKey:   "1",
						}),
					)), relaxedCertificateRequestMatcher),
			},
		},
		"do nothing if existing CertificateRequest is valid for the spec": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: bundle1.privateKeyBytes},
				},
			},
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("random-value"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "1",
					}),
				),
			},
		},
		"should delete requests that contain invalid CSR data": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: bundle1.privateKeyBytes},
				},
			},
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("random-value"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "1",
					}),
					gen.SetCertificateRequestCSR([]byte("invalid")),
				),
			},
			expectedEvents: []string{`Normal Requested Created new CertificateRequest resource "test-1"`},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns", "random-value")),
				testpkg.NewCustomMatch(coretesting.NewCreateAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns",
					gen.CertificateRequestFrom(bundle1.certificateRequest,
						gen.SetCertificateRequestName("test-1"),
						gen.SetCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
							cmapi.CertificateRequestRevisionAnnotationKey:   "1",
						}),
					)), relaxedCertificateRequestMatcher),
			},
		},
		"should ignore requests that do not have a revision of 'current + 1' and create a new one": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: mustGenerateRSA(t)},
				},
			},
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("test-3"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "3",
					}),
				),
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("test-4"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "4",
					}),
				),
			},
			expectedEvents: []string{`Normal Requested Created new CertificateRequest resource "test-1"`},
			expectedActions: []testpkg.Action{
				testpkg.NewCustomMatch(coretesting.NewCreateAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns",
					gen.CertificateRequestFrom(bundle1.certificateRequest,
						gen.SetCertificateRequestName("test-1"),
						gen.SetCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
							cmapi.CertificateRequestRevisionAnnotationKey:   "1",
						}),
					)), relaxedCertificateRequestMatcher),
			},
		},
		"should delete request for the current revision if public keys do not match": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: mustGenerateRSA(t)},
				},
			},
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("test-1"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "1",
					}),
				),
				// included here just to ensure it does not get deleted as it is not for the
				// 'next' revision that is being requested
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("test-4"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "4",
					}),
				),
			},
			expectedEvents: []string{`Normal Requested Created new CertificateRequest resource "test-1"`},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns", "test")),
				testpkg.NewCustomMatch(coretesting.NewCreateAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns",
					gen.CertificateRequestFrom(bundle1.certificateRequest,
						gen.SetCertificateRequestName("test-1"),
						gen.SetCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
							cmapi.CertificateRequestRevisionAnnotationKey:   "1",
						}),
					)), relaxedCertificateRequestMatcher),
			},
		},
		"should delete request for the current revision if public keys do not match (with explicit revision)": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: bundle2.privateKeyBytes},
				},
			},
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
				gen.SetCertificateRevision(5),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("test-6"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "6",
					}),
				),
				// included here just to ensure it does not get deleted as it is not for the
				// 'next' revision that is being requested
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("test-5"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "5",
					}),
				),
			},
			expectedEvents: []string{`Normal Requested Created new CertificateRequest resource "test-6"`},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns", "test-6")),
				testpkg.NewCustomMatch(coretesting.NewCreateAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns",
					gen.CertificateRequestFrom(bundle2.certificateRequest,
						gen.SetCertificateRequestName("test-6"),
						gen.SetCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
							cmapi.CertificateRequestRevisionAnnotationKey:   "6",
						}),
					)), relaxedCertificateRequestMatcher),
			},
		},
		"should recreate the CertificateRequest if the CSR is not signed by the stored private key": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: mustGenerateRSA(t)},
				},
			},
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
				gen.SetCertificateRevision(5),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("test-6"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "6",
					}),
				),
			},
			expectedEvents: []string{`Normal Requested Created new CertificateRequest resource "test-6"`},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns", "test-6")),
				testpkg.NewCustomMatch(coretesting.NewCreateAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns",
					gen.CertificateRequestFrom(bundle1.certificateRequest,
						gen.SetCertificateRequestName("test-6"),
						gen.SetCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
							cmapi.CertificateRequestRevisionAnnotationKey:   "6",
						}),
					)), relaxedCertificateRequestMatcher),
			},
		},
		"should recreate the CertificateRequest if the CSR does not match requirements on spec": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: bundle1.privateKeyBytes},
				},
			},
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateCommonName("something-different"),
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
				gen.SetCertificateRevision(5),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("test-6"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "6",
					}),
				),
			},
			expectedEvents: []string{`Normal Requested Created new CertificateRequest resource "test-6"`},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns", "test-6")),
				testpkg.NewCustomMatch(coretesting.NewCreateAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns",
					gen.CertificateRequestFrom(bundle1.certificateRequest,
						gen.SetCertificateRequestName("test-6"),
						gen.SetCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
							cmapi.CertificateRequestRevisionAnnotationKey:   "6",
						}),
					)), relaxedCertificateRequestMatcher),
			},
		},
		"should do nothing if request has an up to date CSR and it is still pending": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: bundle1.privateKeyBytes},
				},
			},
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
				gen.SetCertificateRevision(5),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("random-value"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "6",
					}),
				),
			},
		},
		"should do nothing if multiple owned and up to date CertificateRequests for the current revision exist": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: bundle1.privateKeyBytes},
				},
			},
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}),
				gen.SetCertificateRevision(5),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("random-value-1"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "6",
					}),
				),
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("random-value-2"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "6",
					}),
				),
			},
		},
		"should recreate the CertificateRequest if the current 'next' CertificateRequest failed during previous issuance cycle": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: bundle1.privateKeyBytes},
				},
			},
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue, LastTransitionTime: &fixedNow}),
				gen.SetCertificateRevision(5),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("test-6"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "6",
					}),
					gen.AddCertificateRequestStatusCondition(failedCRConditionPreviousIssuance),
					gen.SetCertificateRequestFailureTime(metav1.Time{Time: fixedNow.Time.Add(time.Hour * -1)}),
				),
			},
			expectedEvents: []string{`Normal Requested Created new CertificateRequest resource "test-6"`},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns", "test-6")),
				testpkg.NewCustomMatch(coretesting.NewCreateAction(cmapi.SchemeGroupVersion.WithResource("certificaterequests"), "testns",
					gen.CertificateRequestFrom(bundle1.certificateRequest,
						gen.SetCertificateRequestName("test-6"),
						gen.SetCertificateRequestAnnotations(map[string]string{
							cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
							cmapi.CertificateRequestRevisionAnnotationKey:   "6",
						}),
					)), relaxedCertificateRequestMatcher),
			},
		},
		"should do nothing if the CertificateRequest that is valid for spec has failed during this issuance cycle": {
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "exists"},
					Data:       map[string][]byte{corev1.TLSPrivateKeyKey: bundle1.privateKeyBytes},
				},
			},
			certificate: gen.CertificateFrom(bundle1.certificate,
				gen.SetCertificateNextPrivateKeySecretName("exists"),
				gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue, LastTransitionTime: &fixedNow}),
				gen.SetCertificateRevision(5),
			),
			requests: []runtime.Object{
				gen.CertificateRequestFrom(bundle1.certificateRequest,
					gen.SetCertificateRequestName("random-value"),
					gen.SetCertificateRequestAnnotations(map[string]string{
						cmapi.CertificateRequestPrivateKeyAnnotationKey: "exists",
						cmapi.CertificateRequestRevisionAnnotationKey:   "6",
					}),
					gen.AddCertificateRequestStatusCondition(failedCRConditionThisIssuance),
					gen.SetCertificateRequestFailureTime(metav1.Time{Time: fixedNow.Time.Add(1 * time.Minute)}),
				),
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create and initialise a new unit test builder
			builder := &testpkg.Builder{
				T:               t,
				ExpectedEvents:  test.expectedEvents,
				ExpectedActions: test.expectedActions,
				StringGenerator: func(i int) string { return "notrandom" },
				Clock:           fixedClock,
			}
			if test.certificate != nil {
				builder.CertManagerObjects = append(builder.CertManagerObjects, test.certificate)
			}
			if test.secrets != nil {
				builder.KubeObjects = append(builder.KubeObjects, test.secrets...)
			}
			builder.CertManagerObjects = append(builder.CertManagerObjects, test.requests...)
			builder.Init()

			// Register informers used by the controller using the registration wrapper
			w := &controllerWrapper{}
			_, _, err := w.Register(builder.Context)
			if err != nil {
				t.Fatal(err)
			}

			// Enable any features for a particular test
			for feature, value := range test.featuresFlags {
				featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature, value)
			}

			// Start the informers and begin processing updates
			builder.Start()
			defer builder.Stop()

			key := test.key
			if key == (types.NamespacedName{}) && test.certificate != nil {
				key = types.NamespacedName{
					Name:      test.certificate.Name,
					Namespace: test.certificate.Namespace,
				}
			}

			// Call ProcessItem
			err = w.controller.ProcessItem(context.Background(), key)
			switch {
			case err != nil:
				if test.err != err.Error() {
					t.Errorf("error text did not match, got=%s, exp=%s", err.Error(), test.err)
				}
			default:
				if test.err != "" {
					t.Errorf("got no error but expected: %s", test.err)
				}
			}

			if err := builder.AllEventsCalled(); err != nil {
				builder.T.Error(err)
			}
			if err := builder.AllActionsExecuted(); err != nil {
				builder.T.Error(err)
			}
		})
	}
}
