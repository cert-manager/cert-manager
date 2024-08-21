/*
Copyright 2021 The cert-manager Authors.

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

package acme

import (
	"context"
	"crypto/x509"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authzv1 "k8s.io/api/authorization/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)

	certificatesigningrequestGVK = schema.GroupVersionKind{Group: "certificates.k8s.io", Version: "v1", Kind: "CertificateSigningRequest"}
)

func Test_controllerBuilder(t *testing.T) {
	baseCSR := gen.CertificateSigningRequest("test-csr",
		gen.SetCertificateSigningRequestCertificate([]byte("csr")),
	)

	baseOrder := gen.Order("test-order",
		gen.SetOrderNamespace("test-namespace"),
	)

	tests := map[string]struct {
		existingCSR       runtime.Object
		existingCMObjects []runtime.Object
		givenCall         func(*testing.T, cmclient.Interface, kubernetes.Interface)
		expectRequeueKey  types.NamespacedName
	}{
		"if no request then no request should sync": {
			existingCSR:       nil,
			existingCMObjects: []runtime.Object{baseOrder},
			givenCall:         func(t *testing.T, _ cmclient.Interface, _ kubernetes.Interface) {},
			expectRequeueKey:  types.NamespacedName{},
		},
		"if no changes to request or order, then no request should sync": {
			existingCSR:       baseCSR,
			existingCMObjects: []runtime.Object{baseOrder},
			givenCall:         func(t *testing.T, _ cmclient.Interface, _ kubernetes.Interface) {},
			expectRequeueKey:  types.NamespacedName{},
		},
		"request should be synced if an owned order is updated": {
			existingCSR: baseCSR,
			existingCMObjects: []runtime.Object{
				gen.OrderFrom(baseOrder,
					gen.SetOrderOwnerReference(*metav1.NewControllerRef(baseCSR, certificatesigningrequestGVK)),
				),
			},
			givenCall: func(t *testing.T, cmclient cmclient.Interface, _ kubernetes.Interface) {
				order := gen.OrderFrom(baseOrder,
					gen.SetOrderOwnerReference(*metav1.NewControllerRef(baseCSR, certificatesigningrequestGVK)),
					gen.SetOrderURL("update"),
				)
				_, err := cmclient.AcmeV1().Orders("test-namespace").Update(context.TODO(), order, metav1.UpdateOptions{})
				require.NoError(t, err)
			},
			expectRequeueKey: types.NamespacedName{
				Name: "test-csr",
			},
		},
		"request should not be synced if updated order is not owned": {
			existingCSR: baseCSR,
			existingCMObjects: []runtime.Object{
				gen.OrderFrom(baseOrder),
			},
			givenCall: func(t *testing.T, cmclient cmclient.Interface, _ kubernetes.Interface) {
				order := gen.OrderFrom(baseOrder,
					gen.SetOrderURL("update"),
				)
				_, err := cmclient.AcmeV1().Orders("test-namespace").Update(context.TODO(), order, metav1.UpdateOptions{})
				require.NoError(t, err)
			},
			expectRequeueKey: types.NamespacedName{},
		},
		"request should be synced if request is updated": {
			existingCSR:       baseCSR,
			existingCMObjects: []runtime.Object{baseOrder},
			givenCall: func(t *testing.T, _ cmclient.Interface, kubeclient kubernetes.Interface) {
				csr := gen.CertificateSigningRequestFrom(baseCSR,
					gen.SetCertificateSigningRequestCertificate([]byte("update")),
				)
				_, err := kubeclient.CertificatesV1().CertificateSigningRequests().UpdateStatus(context.TODO(), csr, metav1.UpdateOptions{})
				require.NoError(t, err)
			},
			expectRequeueKey: types.NamespacedName{
				Name: "test-csr",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			b := &testpkg.Builder{T: t, CertManagerObjects: test.existingCMObjects}
			if test.existingCSR != nil {
				b.KubeObjects = append(b.KubeObjects, test.existingCSR)
			}
			b.Init()

			queue, hasSynced, err := controllerBuilder().Register(b.Context)
			require.NoError(t, err)

			b.Start()
			defer b.Stop()

			for _, hs := range hasSynced {
				require.True(t, hs())
			}

			// Remove all objects from the queue before continuing.
			for queue.Len() != 0 {
				o, _ := queue.Get()
				queue.Done(o)
			}

			test.givenCall(t, b.CMClient, b.Client)

			// We have no way of knowing when the informers will be done adding
			// items to the queue due to the "shared informer" architecture:
			// Start(stop) does not allow you to wait for the informers to be
			// done. To work around that, we do a second queue.Get and expect it
			// to be nil.
			time.AfterFunc(50*time.Millisecond, queue.ShutDown)

			var gotKeys []types.NamespacedName
			for {
				// Get blocks until either (1) a key is returned, or (2) the
				// queue is shut down.
				gotKey, done := queue.Get()
				if done {
					break
				}
				gotKeys = append(gotKeys, gotKey)
			}
			assert.Equal(t, 0, queue.Len(), "queue should be empty")

			// We only expect 0 or 1 keys received in the queue.
			if test.expectRequeueKey != (types.NamespacedName{}) {
				assert.Equal(t, []types.NamespacedName{test.expectRequeueKey}, gotKeys)
			} else {
				assert.Nil(t, gotKeys)
			}
		})
	}
}

func Test_ProcessItem(t *testing.T) {
	metaFixedClockStart := metav1.NewTime(fixedClockStart)
	util.Clock = fixedClock

	baseIssuer := gen.Issuer("test-issuer",
		gen.SetIssuerACME(cmacme.ACMEIssuer{}),
		gen.AddIssuerCondition(cmapi.IssuerCondition{
			Type:   cmapi.IssuerConditionReady,
			Status: cmmeta.ConditionTrue,
		}),
	)

	csrPEM, sk, err := gen.CSR(x509.ECDSA,
		gen.SetCSRCommonName("example.com"),
		gen.SetCSRDNSNames("example.com"),
	)
	if err != nil {
		t.Fatal(err)
	}

	req, err := pki.DecodeX509CertificateRequestBytes(csrPEM)
	if err != nil {
		t.Fatal(err)
	}

	csrPEMExampleNotPresent, skExampleNotPresent, err := gen.CSR(x509.ECDSA,
		gen.SetCSRCommonName("example.com"),
		gen.SetCSRDNSNames("foo.com"),
	)
	if err != nil {
		t.Fatal(err)
	}

	baseCSR := gen.CertificateSigningRequest("test-csr",
		gen.SetCertificateSigningRequestRequest(csrPEM),
		gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/default-unit-test-ns.test-issuer"),
		gen.SetCertificateSigningRequestDuration("1440h"),
		gen.SetCertificateSigningRequestUsername("user-1"),
		gen.SetCertificateSigningRequestGroups([]string{"group-1", "group-2"}),
		gen.SetCertificateSigningRequestUID("uid-1"),
		gen.SetCertificateSigningRequestExtra(map[string]certificatesv1.ExtraValue{
			"extra": []string{"1", "2"},
		}),
	)

	tmpl, err := pki.CertificateTemplateFromCertificateSigningRequest(baseCSR)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := pki.SignCertificate(tmpl, tmpl, sk.Public(), sk)
	if err != nil {
		t.Fatal(err)
	}

	tmpl, err = pki.CertificateTemplateFromCertificateSigningRequest(gen.CertificateSigningRequestFrom(baseCSR,
		gen.SetCertificateSigningRequestRequest(csrPEMExampleNotPresent),
	))
	if err != nil {
		t.Fatal(err)
	}
	certPEMExampleNotPresent, _, err := pki.SignCertificate(tmpl, tmpl, skExampleNotPresent.Public(), skExampleNotPresent)
	if err != nil {
		t.Fatal(err)
	}

	baseOrder, err := new(ACME).buildOrder(baseCSR, req, baseIssuer)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		builder     *testpkg.Builder
		csr         *certificatesv1.CertificateSigningRequest
		expectedErr bool
	}{
		"a CertificateSigningRequest without an approved condition should fire an event": {
			csr: gen.CertificateSigningRequestFrom(baseCSR),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal WaitingApproval Waiting for the Approved condition before issuing",
				},
			},
		},
		"a CertificateSigningRequest with a denied condition should do nothing": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateDenied,
					Status: corev1.ConditionTrue,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents:     []string{},
				ExpectedActions:    nil,
			},
		},
		"an approved CSR that contains a garbage request should be marked as Failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestRequest([]byte("garbage-data")),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning RequestParsingError Failed to decode CSR in spec.request: error decoding certificate request PEM block",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"),
						"status",
						"",
						gen.CertificateSigningRequestFrom(baseCSR.DeepCopy(),
							gen.SetCertificateSigningRequestRequest([]byte("garbage-data")),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "RequestParsingError",
								Message:            "Failed to decode CSR in spec.request: error decoding certificate request PEM block",
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR where the common name is not included in the DNS Names be marked as Failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestRequest(csrPEMExampleNotPresent),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Warning InvalidOrder The CSR PEM requests a commonName that is not present in the list of dnsNames or ipAddresses. If a commonName is set, ACME requires that the value is also present in the list of dnsNames or ipAddresses: "example.com" does not exist in [foo.com] or []`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"),
						"status",
						"",
						gen.CertificateSigningRequestFrom(baseCSR.DeepCopy(),
							gen.SetCertificateSigningRequestRequest(csrPEMExampleNotPresent),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "InvalidOrder",
								Message:            `The CSR PEM requests a commonName that is not present in the list of dnsNames or ipAddresses. If a commonName is set, ACME requires that the value is also present in the list of dnsNames or ipAddresses: "example.com" does not exist in [foo.com] or []`,
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR which contains a garbage duration and has duration enabled, should fail when parsing duration and be marked as Failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestDuration("garbage-data"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.IssuerFrom(baseIssuer.DeepCopy(),
						gen.SetIssuerACME(cmacme.ACMEIssuer{EnableDurationFeature: true}),
					)},
				ExpectedEvents: []string{
					`Warning ErrorParseDuration Failed to parse requested duration: failed to parse requested duration on annotation "experimental.cert-manager.io/request-duration": time: invalid duration "garbage-data"`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"),
						"status",
						"",
						gen.CertificateSigningRequestFrom(baseCSR.DeepCopy(),
							gen.SetCertificateSigningRequestDuration("garbage-data"),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "ErrorParseDuration",
								Message:            `Failed to parse requested duration: failed to parse requested duration on annotation "experimental.cert-manager.io/request-duration": time: invalid duration "garbage-data"`,
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR where the order does not yet exist, should create the order and fire an event": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.IssuerFrom(baseIssuer.DeepCopy(),
						gen.SetIssuerACME(cmacme.ACMEIssuer{}),
					)},
				ExpectedEvents: []string{
					`Normal OrderCreated Created Order resource default-unit-test-ns/test-csr-3290353799`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
					testpkg.NewAction(coretesting.NewCreateAction(
						cmacme.SchemeGroupVersion.WithResource("orders"),
						gen.DefaultTestNamespace,
						baseOrder,
					)),
				},
			},
		},
		"an approved CSR where the order already exists, but is owned by another CSR, return error": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			expectedErr: true,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.IssuerFrom(baseIssuer.DeepCopy(),
						gen.SetIssuerACME(cmacme.ACMEIssuer{}),
					),
					gen.OrderFrom(baseOrder,
						gen.SetOrderOwnerReference(metav1.OwnerReference{}),
					),
				},
				ExpectedEvents: []string{},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
				},
			},
		},
		"an approved CSR where the order already exists but is in a Failure state should mark the CSR and Failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.IssuerFrom(baseIssuer.DeepCopy(),
						gen.SetIssuerACME(cmacme.ACMEIssuer{}),
					),
					gen.OrderFrom(baseOrder,
						gen.SetOrderStatus(cmacme.OrderStatus{
							Reason: "generic error",
							State:  cmacme.Invalid,
						}),
					),
				},
				ExpectedEvents: []string{
					`Warning OrderFailed Failed to wait for order resource default-unit-test-ns/test-csr-3290353799 to become ready: order is in "invalid" state: generic error`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"),
						"status",
						"",
						gen.CertificateSigningRequestFrom(baseCSR.DeepCopy(),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "OrderFailed",
								Message:            `Failed to wait for order resource default-unit-test-ns/test-csr-3290353799 to become ready: order is in "invalid" state: generic error`,
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR where the order is not in a Valid state should fire an event and return": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.IssuerFrom(baseIssuer.DeepCopy(),
						gen.SetIssuerACME(cmacme.ACMEIssuer{}),
					),
					gen.OrderFrom(baseOrder,
						gen.SetOrderStatus(cmacme.OrderStatus{
							Reason: "pending",
							State:  cmacme.Pending,
						}),
					),
				},
				ExpectedEvents: []string{
					`Normal OrderPending Waiting on certificate issuance from order default-unit-test-ns/test-csr-3290353799: "pending"`,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
				},
			},
		},
		"an approved CSR where the order is in a valid state, but the Certificate is empty should fire an event": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.IssuerFrom(baseIssuer.DeepCopy(),
						gen.SetIssuerACME(cmacme.ACMEIssuer{}),
					),
					gen.OrderFrom(baseOrder,
						gen.SetOrderStatus(cmacme.OrderStatus{
							State: cmacme.Valid,
						}),
						gen.SetOrderCertificate(nil),
					),
				},
				ExpectedEvents: []string{
					"Normal OrderPending Waiting for order-controller to add certificate data to Order default-unit-test-ns/test-csr-3290353799",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
				},
			},
		},
		"an approved CSR where the order is in a valid state, but the certificate is garbage, should delete the Order and fire an event": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.IssuerFrom(baseIssuer.DeepCopy(),
						gen.SetIssuerACME(cmacme.ACMEIssuer{}),
					),
					gen.OrderFrom(baseOrder,
						gen.SetOrderStatus(cmacme.OrderStatus{
							State: cmacme.Valid,
						}),
						gen.SetOrderCertificate([]byte("garbage-data")),
					),
				},
				ExpectedEvents: []string{
					"Warning OrderBadCertificate Deleting Order with bad certificate: error decoding certificate PEM block",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
					testpkg.NewAction(coretesting.NewDeleteAction(
						cmacme.SchemeGroupVersion.WithResource("orders"),
						gen.DefaultTestNamespace,
						baseOrder.Name,
					)),
				},
			},
		},
		"an approved CSR where the order is in a valid state, but the certificate is singed for a different key than the request, delete the order": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.IssuerFrom(baseIssuer.DeepCopy(),
						gen.SetIssuerACME(cmacme.ACMEIssuer{}),
					),
					gen.OrderFrom(baseOrder,
						gen.SetOrderStatus(cmacme.OrderStatus{
							State: cmacme.Valid,
						}),
						gen.SetOrderCertificate(certPEMExampleNotPresent),
					),
				},
				ExpectedEvents: []string{
					"Warning OrderBadCertificate Deleting Order as the signed certificate's key does not match the request",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
					testpkg.NewAction(coretesting.NewDeleteAction(
						cmacme.SchemeGroupVersion.WithResource("orders"),
						gen.DefaultTestNamespace,
						baseOrder.Name,
					)),
				},
			},
		},
		"an approved CSR where the order is in a valid state, should update the CSR with the Certificate": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.IssuerFrom(baseIssuer.DeepCopy(),
						gen.SetIssuerACME(cmacme.ACMEIssuer{}),
					),
					gen.OrderFrom(baseOrder,
						gen.SetOrderStatus(cmacme.OrderStatus{
							State:       cmacme.Valid,
							Certificate: certPEM,
						}),
						gen.SetOrderCertificate(certPEM),
					),
				},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate fetched from issuer successfully",
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						&authzv1.SubjectAccessReview{
							Spec: authzv1.SubjectAccessReviewSpec{
								User:   "user-1",
								Groups: []string{"group-1", "group-2"},
								Extra: map[string]authzv1.ExtraValue{
									"extra": []string{"1", "2"},
								},
								UID: "uid-1",

								ResourceAttributes: &authzv1.ResourceAttributes{
									Group:     certmanager.GroupName,
									Resource:  "signers",
									Verb:      "reference",
									Namespace: baseIssuer.Namespace,
									Name:      baseIssuer.Name,
									Version:   "*",
								},
							},
						},
					)),
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"),
						"status",
						"",
						gen.CertificateSigningRequestFrom(baseCSR,
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestCertificate(certPEM),
						),
					)),
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.csr != nil {
				test.builder.KubeObjects = append(test.builder.KubeObjects, test.csr)
			}

			fixedClock.SetTime(fixedClockStart)
			test.builder.Clock = fixedClock
			test.builder.T = t
			test.builder.Init()

			// Always return true for SubjectAccessReviews in tests
			test.builder.FakeKubeClient().PrependReactor("create", "*", func(action coretesting.Action) (bool, runtime.Object, error) {
				if action.GetResource() != authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews") {
					return false, nil, nil
				}
				return true, &authzv1.SubjectAccessReview{
					Status: authzv1.SubjectAccessReviewStatus{
						Allowed: true,
					},
				}, nil
			})

			defer test.builder.Stop()

			controller := controllerBuilder()
			if _, _, err := controller.Register(test.builder.Context); err != nil {
				t.Fatal(err)
			}

			test.builder.Start()

			err := controller.ProcessItem(context.Background(), types.NamespacedName{
				Name: test.csr.Name,
			})
			if (err != nil) != test.expectedErr {
				t.Errorf("unexpected error, exp=%t got=%v", test.expectedErr, err)
			}

			test.builder.CheckAndFinish(err)
		})
	}
}

func Test_buildOrder(t *testing.T) {
	csrPEM, _, err := gen.CSR(x509.ECDSA,
		gen.SetCSRCommonName("example.com"),
		gen.SetCSRDNSNames("example.com"),
	)
	if err != nil {
		t.Fatal(err)
	}

	req, err := pki.DecodeX509CertificateRequestBytes(csrPEM)
	if err != nil {
		t.Fatal(err)
	}

	csr := gen.CertificateSigningRequest("test",
		gen.SetCertificateSigningRequestDuration("1h"),
		gen.SetCertificateSigningRequestRequest(csrPEM),
		gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/test-ns.test-name"),
	)

	tests := map[string]struct {
		enableDurationFeature bool

		want    *cmacme.Order
		wantErr bool
	}{
		"Normal building of order": {
			enableDurationFeature: false,
			want: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					Request:    csrPEM,
					CommonName: "example.com",
					DNSNames:   []string{"example.com"},
					IssuerRef: cmmeta.ObjectReference{
						Name:  "test-name",
						Kind:  "Issuer",
						Group: "cert-manager.io",
					},
				},
			},
			wantErr: false,
		},
		"Building with enableDurationFeature": {
			enableDurationFeature: true,
			want: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					Request:    csrPEM,
					CommonName: "example.com",
					DNSNames:   []string{"example.com"},
					Duration:   &metav1.Duration{Duration: time.Hour},
					IssuerRef: cmmeta.ObjectReference{
						Name:  "test-name",
						Kind:  "Issuer",
						Group: "cert-manager.io",
					},
				},
			},
			wantErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := new(ACME).buildOrder(csr, req, &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							EnableDurationFeature: test.enableDurationFeature,
						},
					},
				},
			})
			if (err != nil) != test.wantErr {
				t.Errorf("buildOrder() error = %v, wantErr %v", err, test.wantErr)
				return
			}

			// for the current purpose we only test the spec
			if !reflect.DeepEqual(got.Spec, test.want.Spec) {
				t.Errorf("buildOrder() got = %v, want %v", got.Spec, test.want.Spec)
			}
		})
	}

	longCSROne := gen.CertificateSigningRequest(
		"test-comparison-that-is-at-the-fifty-two-character-l",
		gen.SetCertificateSigningRequestDuration("1h"),
		gen.SetCertificateSigningRequestRequest(csrPEM),
		gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/test-ns.test-name"),
	)
	orderOne, err := new(ACME).buildOrder(longCSROne, req, gen.Issuer("test-name", gen.SetIssuerACME(cmacme.ACMEIssuer{})))
	if err != nil {
		t.Errorf("buildOrder() received error %v", err)
		return
	}

	t.Run("Builds two orders from different long CSRs to guarantee unique name", func(t *testing.T) {
		longCSRTwo := gen.CertificateSigningRequest(
			"test-comparison-that-is-at-the-fifty-two-character-l-two",
			gen.SetCertificateSigningRequestDuration("1h"),
			gen.SetCertificateSigningRequestRequest(csrPEM),
			gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/test-ns.test-name"),
		)

		orderTwo, err := new(ACME).buildOrder(longCSRTwo, req, gen.Issuer("test-name", gen.SetIssuerACME(cmacme.ACMEIssuer{})))
		if err != nil {
			t.Errorf("buildOrder() received error %v", err)
			return
		}

		if orderOne.Name == orderTwo.Name {
			t.Errorf(
				"orders built from different CSRs have equal names: %s == %s",
				orderOne.Name,
				orderTwo.Name)
		}
	})

	t.Run("Builds two orders from the same long CSRs to guarantee same name", func(t *testing.T) {
		orderOne, err := new(ACME).buildOrder(longCSROne, req, gen.Issuer("test-name", gen.SetIssuerACME(cmacme.ACMEIssuer{})))
		if err != nil {
			t.Errorf("buildOrder() received error %v", err)
			return
		}

		orderTwo, err := new(ACME).buildOrder(longCSROne, req, gen.Issuer("test-name", gen.SetIssuerACME(cmacme.ACMEIssuer{})))
		if err != nil {
			t.Errorf("buildOrder() received error %v", err)
			return
		}
		if orderOne.Name != orderTwo.Name {
			t.Errorf(
				"orders built from the same CSR have unequal names: %s != %s",
				orderOne.Name,
				orderTwo.Name)
		}
	})
}
