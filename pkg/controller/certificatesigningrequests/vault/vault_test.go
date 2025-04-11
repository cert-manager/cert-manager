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

package vault

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	internalvault "github.com/cert-manager/cert-manager/internal/vault"
	fakevault "github.com/cert-manager/cert-manager/internal/vault/fake"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func TestProcessItem(t *testing.T) {
	metaFixedClockStart := metav1.NewTime(fixedClockStart)
	util.Clock = fixedClock

	baseIssuer := gen.Issuer("test-issuer",
		gen.SetIssuerVault(cmapi.VaultIssuer{
			Auth: cmapi.VaultAuth{
				Kubernetes: &cmapi.VaultKubernetesAuth{
					Path: "/v1/kubernetes",
					Role: "kube-pki",
					SecretRef: cmmeta.SecretKeySelector{
						Key: "token",
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: "sa-token",
						},
					},
				},
			},
			Server: "https://example.vault.com",
		}),
		gen.AddIssuerCondition(cmapi.IssuerCondition{
			Type:   cmapi.IssuerConditionReady,
			Status: cmmeta.ConditionTrue,
		}),
	)

	csrPEM, _, err := gen.CSR(x509.RSA)
	if err != nil {
		t.Fatal(err)
	}

	baseCSR := gen.CertificateSigningRequest("test-cr",
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

	tests := map[string]struct {
		builder       *testpkg.Builder
		csr           *certificatesv1.CertificateSigningRequest
		clientBuilder internalvault.ClientBuilder
		expectedErr   bool
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
		"an approved CSR where the vault client builder returns a not found error should mark as Failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ context.Context, _ string, _ func(ns string) internalvault.CreateToken, _ internalinformers.SecretLister, _ cmapi.GenericIssuer) (internalvault.Interface, error) {
				return nil, apierrors.NewNotFound(schema.GroupResource{}, "test-secret")
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning SecretNotFound Required secret resource not found",
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
								Reason:             "SecretNotFound",
								Message:            "Required secret resource not found",
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR where the vault client builder returns a generic error should return error to retry": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ context.Context, _ string, _ func(ns string) internalvault.CreateToken, _ internalinformers.SecretLister, _ cmapi.GenericIssuer) (internalvault.Interface, error) {
				return nil, errors.New("generic error")
			},
			expectedErr: true,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning ErrorVaultInit Failed to initialise vault client for signing: generic error",
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
		"an approved CSR which has an invalid duration string should be marked as Failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestDuration("bad-duration"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ context.Context, _ string, _ func(ns string) internalvault.CreateToken, _ internalinformers.SecretLister, _ cmapi.GenericIssuer) (internalvault.Interface, error) {
				return fakevault.New(), nil
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					`Warning ErrorParseDuration Failed to parse requested duration: failed to parse requested duration on annotation "experimental.cert-manager.io/request-duration": time: invalid duration "bad-duration"`,
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
							gen.SetCertificateSigningRequestDuration("bad-duration"),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:   certificatesv1.CertificateApproved,
								Status: corev1.ConditionTrue,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "ErrorParseDuration",
								Message:            `Failed to parse requested duration: failed to parse requested duration on annotation "experimental.cert-manager.io/request-duration": time: invalid duration "bad-duration"`,
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR which errors when invoking sign on the vault client should mark the CSR as Failed": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ context.Context, _ string, _ func(ns string) internalvault.CreateToken, _ internalinformers.SecretLister, _ cmapi.GenericIssuer) (internalvault.Interface, error) {
				return fakevault.New().WithSign(nil, nil, errors.New("sign error")), nil
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Warning ErrorSigning Vault failed to sign: sign error",
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
								Reason:             "ErrorSigning",
								Message:            "Vault failed to sign: sign error",
								LastTransitionTime: metaFixedClockStart,
								LastUpdateTime:     metaFixedClockStart,
							}),
						),
					)),
				},
			},
		},
		"an approved CSR which successfully signs, should update the Certificate field": {
			csr: gen.CertificateSigningRequestFrom(baseCSR,
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:   certificatesv1.CertificateApproved,
					Status: corev1.ConditionTrue,
				}),
			),
			clientBuilder: func(_ context.Context, _ string, _ func(ns string) internalvault.CreateToken, _ internalinformers.SecretLister, _ cmapi.GenericIssuer) (internalvault.Interface, error) {
				return fakevault.New().WithSign([]byte("signed-cert"), []byte("signing-ca"), nil), nil
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{baseIssuer.DeepCopy()},
				ExpectedEvents: []string{
					"Normal CertificateIssued Certificate signed successfully",
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
							gen.SetCertificateSigningRequestCertificate([]byte("signed-cert")),
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

			vault := NewVault(test.builder.Context).(*Vault)
			vault.clientBuilder = test.clientBuilder

			controller := certificatesigningrequests.New(
				apiutil.IssuerVault,
				func(*controllerpkg.Context) certificatesigningrequests.Signer { return vault },
			)
			if _, _, err := controller.Register(test.builder.Context); err != nil {
				t.Fatal(err)
			}
			test.builder.Start()

			err := controller.ProcessItem(context.Background(), types.NamespacedName{
				Name: test.csr.Name,
			})
			if err != nil && !test.expectedErr {
				t.Errorf("expected to not get an error, but got: %v", err)
			}
			if err == nil && test.expectedErr {
				t.Errorf("expected to get an error but did not get one")
			}

			test.builder.CheckAndFinish(err)
		})
	}
}
