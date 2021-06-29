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

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	authzv1 "k8s.io/api/authorization/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/controller/certificatesigningrequests"
	"github.com/jetstack/cert-manager/pkg/controller/certificatesigningrequests/util"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func TestProcessItem(t *testing.T) {
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

	tmpl, err := pki.GenerateTemplateFromCertificateSigningRequest(baseCSR)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := pki.SignCertificate(tmpl, tmpl, sk.Public(), sk)
	if err != nil {
		t.Fatal(err)
	}

	tmpl, err = pki.GenerateTemplateFromCertificateSigningRequest(gen.CertificateSigningRequestFrom(baseCSR,
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
		"a CertificateSigningRequest without an approved condition should do nothing": {
			csr: gen.CertificateSigningRequestFrom(baseCSR),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
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
		"an approved CSR which contains a garbage duration and has duration enabled, should fail when building the order and be marked as Failed": {
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
					`Warning OrderBuildingError Failed to build order: failed to parse requested duration on annotation "experimental.cert-manager.io/request-duration": time: invalid duration "garbage-data"`,
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
								Reason:             "OrderBuildingError",
								Message:            `Failed to build order: failed to parse requested duration on annotation "experimental.cert-manager.io/request-duration": time: invalid duration "garbage-data"`,
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

			acme := NewACME(test.builder.Context)

			controller := certificatesigningrequests.New(apiutil.IssuerACME, acme)
			controller.Register(test.builder.Context)

			test.builder.Start()

			err := controller.ProcessItem(context.Background(), test.csr.Name)
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
