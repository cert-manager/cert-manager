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

package certificatesigningrequests

import (
	"context"
	"errors"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/fake"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestController(t *testing.T) {
	fixedClockStart := time.Now()
	fixedClock := fakeclock.NewFakeClock(fixedClockStart)
	metaFixedClockStart := metav1.NewTime(fixedClockStart)

	signerExpectNoCall := func(t *testing.T) Signer {
		return &fake.Signer{
			FakeSign: func(context.Context, *certificatesv1.CertificateSigningRequest, cmapi.GenericIssuer) error {
				t.Fatal("unexpected sign call")
				return nil
			},
		}
	}

	sarReactionExpectNoCall := func(t *testing.T) coretesting.ReactionFunc {
		return func(_ coretesting.Action) (bool, runtime.Object, error) {
			t.Fatal("unexpected call")
			return true, nil, nil
		}
	}
	sarReactionAllow := func(t *testing.T) coretesting.ReactionFunc {
		return func(_ coretesting.Action) (bool, runtime.Object, error) {
			return true, &authzv1.SubjectAccessReview{
				Status: authzv1.SubjectAccessReviewStatus{
					Allowed: true,
				},
			}, nil
		}
	}

	tests := map[string]struct {
		// key that should be passed to ProcessItem. If not set, the
		// 'namespace/name' of the 'CertificateSigningRequest' field will be used.
		// If neither is set, the key will be "".
		key types.NamespacedName

		// CertificateSigningRequest to be synced for the test. If not set, the
		// 'key' will be passed to ProcessItem instead.
		existingCSR *certificatesv1.CertificateSigningRequest

		// If not nil, generic issuer object will be made available for the test
		existingIssuer runtime.Object

		signerType string

		signerImpl      func(t *testing.T) Signer
		sarReaction     func(t *testing.T) coretesting.ReactionFunc
		wantSARCreation []*authzv1.SubjectAccessReview

		// wantEvent, if set, is an 'event string' that is expected to be fired.
		wantEvent string

		// wantConditions is the expected set of conditions on the
		// CertificateSigningRequest resource if an Update is made.
		// If nil, no update is expected.
		// If empty, an update to the empty set/nil is expected.
		wantConditions []certificatesv1.CertificateSigningRequestCondition

		wantErr bool
	}{
		"do nothing if an empty 'key' is used": {
			signerType:  apiutil.IssuerCA,
			signerImpl:  signerExpectNoCall,
			sarReaction: sarReactionExpectNoCall,
		},
		"do nothing if an invalid 'key' is used": {
			key: types.NamespacedName{
				Namespace: "abc",
				Name:      "def/ghi",
			},
			signerType:  apiutil.IssuerCA,
			signerImpl:  signerExpectNoCall,
			sarReaction: sarReactionExpectNoCall,
		},
		"do nothing if a key references a CertificateSigningRequest that does not exist": {
			key: types.NamespacedName{
				Namespace: "namespace",
				Name:      "name",
			},
			signerType:  apiutil.IssuerCA,
			signerImpl:  signerExpectNoCall,
			sarReaction: sarReactionExpectNoCall,
		},
		"do nothing if a key references a CertificateSigningRequest that has a malformed SignerName for cert-manager.io": {
			signerType: apiutil.IssuerCA,
			existingCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestSignerName("malformed.signer.name/"),
			),
			signerImpl:  signerExpectNoCall,
			sarReaction: sarReactionExpectNoCall,
		},
		"if CertificateSigningRequest references the cert-manager.io signer group but the type is not recognised, should ignore": {
			signerType: apiutil.IssuerCA,
			existingCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestSignerName("foo.cert-manager.io/hello.world"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:    certificatesv1.CertificateApproved,
					Status:  corev1.ConditionTrue,
					Reason:  "ApprovedReason",
					Message: "Approved message",
				}),
			),
			signerImpl:  signerExpectNoCall,
			sarReaction: sarReactionExpectNoCall,
		},
		"do nothing if CertificateSigningRequest has a SignerName not for cert-manager.io": {
			signerType: apiutil.IssuerCA,
			existingCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestSignerName("issuers.my-group.io/hello.world"),
			),
			signerImpl:  signerExpectNoCall,
			sarReaction: sarReactionExpectNoCall,
		},
		"do nothing if CertificateSigningRequest is marked as Failed": {
			signerType: apiutil.IssuerCA,
			existingCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/hello.world"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:    certificatesv1.CertificateFailed,
					Status:  corev1.ConditionTrue,
					Reason:  "FailedReason",
					Message: "Failed message",
				}),
			),
			signerImpl:  signerExpectNoCall,
			sarReaction: sarReactionExpectNoCall,
		},
		"fire event if CertificateSigningRequest is no yet approved": {
			signerType: apiutil.IssuerCA,
			existingCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/hello.world"),
			),
			signerImpl:  signerExpectNoCall,
			sarReaction: sarReactionExpectNoCall,
			wantEvent:   "Normal WaitingApproval Waiting for the Approved condition before issuing",
		},
		"do nothing if CertificateSigningRequest already has a non empty Certificate present": {
			signerType: apiutil.IssuerCA,
			existingCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/hello.world"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:    certificatesv1.CertificateApproved,
					Status:  corev1.ConditionTrue,
					Reason:  "ApprovedReason",
					Message: "Approved message",
				}),
				gen.SetCertificateSigningRequestCertificate([]byte("non-empty-certificate")),
			),
			signerImpl:  signerExpectNoCall,
			sarReaction: sarReactionExpectNoCall,
		},
		"if CertificateSigningRequest references an Issuer that does not exist, should fire an event that it can't be found": {
			signerType: apiutil.IssuerCA,
			existingCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/hello.world"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:    certificatesv1.CertificateApproved,
					Status:  corev1.ConditionTrue,
					Reason:  "ApprovedReason",
					Message: "Approved message",
				}),
			),
			signerImpl:     signerExpectNoCall,
			sarReaction:    sarReactionExpectNoCall,
			existingIssuer: nil,
			wantEvent:      "Warning IssuerNotFound Referenced Issuer hello/world not found",
		},
		"if CertificateSigningRequest references an Issuer that does not yet have a type, should fire an event it doesn't have a type": {
			signerType: apiutil.IssuerCA,
			existingCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/hello.world"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:    certificatesv1.CertificateApproved,
					Status:  corev1.ConditionTrue,
					Reason:  "ApprovedReason",
					Message: "Approved message",
				}),
			),
			signerImpl:     signerExpectNoCall,
			sarReaction:    sarReactionExpectNoCall,
			existingIssuer: gen.Issuer("world", gen.SetIssuerNamespace("hello")),
			wantEvent:      "Warning IssuerTypeMissing Referenced Issuer hello/world is missing type",
		},
		"if CertificateSigningRequest references an Issuer which does not match the same signer type, should ignore": {
			signerType: apiutil.IssuerSelfSigned,
			existingCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/hello.world"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:    certificatesv1.CertificateApproved,
					Status:  corev1.ConditionTrue,
					Reason:  "ApprovedReason",
					Message: "Approved message",
				}),
			),
			signerImpl:  signerExpectNoCall,
			sarReaction: sarReactionExpectNoCall,
			existingIssuer: gen.Issuer("world", gen.SetIssuerNamespace("hello"),
				gen.SetIssuerCA(cmapi.CAIssuer{
					SecretName: "tls",
				}),
			),
		},
		"do nothing if CertificateSigningRequest references a signer that is not 'issuers' or 'clusterissuers'": {
			signerType: apiutil.IssuerCA,
			existingCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestSignerName("not-issuers.cert-manager.io/hello.world"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:    certificatesv1.CertificateApproved,
					Status:  corev1.ConditionTrue,
					Reason:  "ApprovedReason",
					Message: "Approved message",
				}),
			),
			signerImpl:  signerExpectNoCall,
			sarReaction: sarReactionExpectNoCall,
		},
		"if CertificateSigningRequest references a issuers signer but the SubjectAccessReview errors, should error": {
			signerType: apiutil.IssuerCA,
			existingCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/hello.world"),
				gen.SetCertificateSigningRequestUsername("user-1"),
				gen.SetCertificateSigningRequestGroups([]string{"group-1", "group-2"}),
				gen.SetCertificateSigningRequestUID("uid-1"),
				gen.SetCertificateSigningRequestExtra(map[string]certificatesv1.ExtraValue{
					"extra": []string{"1", "2"},
				}),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:    certificatesv1.CertificateApproved,
					Status:  corev1.ConditionTrue,
					Reason:  "ApprovedReason",
					Message: "Approved message",
				}),
			),
			signerImpl: signerExpectNoCall,
			sarReaction: func(t *testing.T) coretesting.ReactionFunc {
				return func(_ coretesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("this is a simulated error")
				}
			},
			wantSARCreation: []*authzv1.SubjectAccessReview{
				{
					Spec: authzv1.SubjectAccessReviewSpec{
						User:   "user-1",
						Groups: []string{"group-1", "group-2"},
						Extra: map[string]authzv1.ExtraValue{
							"extra": []string{"1", "2"},
						},
						UID: "uid-1",

						ResourceAttributes: &authzv1.ResourceAttributes{
							Group:     "cert-manager.io",
							Resource:  "signers",
							Verb:      "reference",
							Namespace: "hello",
							Name:      "world",
							Version:   "*",
						},
					},
				},
			},
			existingIssuer: gen.Issuer("world", gen.SetIssuerNamespace("hello"),
				gen.SetIssuerCA(cmapi.CAIssuer{
					SecretName: "tls",
				}),
			),
			wantErr: true,
		},
		"if CertificateSigningRequest references a issuers signer but the requesting user does not have permissions, should update Failed": {
			signerType: apiutil.IssuerCA,
			existingCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/hello.world"),
				gen.SetCertificateSigningRequestUsername("user-1"),
				gen.SetCertificateSigningRequestGroups([]string{"group-1", "group-2"}),
				gen.SetCertificateSigningRequestUID("uid-1"),
				gen.SetCertificateSigningRequestExtra(map[string]certificatesv1.ExtraValue{
					"extra": []string{"1", "2"},
				}),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:    certificatesv1.CertificateApproved,
					Status:  corev1.ConditionTrue,
					Reason:  "ApprovedReason",
					Message: "Approved message",
				}),
			),
			signerImpl: signerExpectNoCall,
			sarReaction: func(t *testing.T) coretesting.ReactionFunc {
				return func(_ coretesting.Action) (bool, runtime.Object, error) {
					return true, &authzv1.SubjectAccessReview{
						Status: authzv1.SubjectAccessReviewStatus{
							Allowed: false,
						},
					}, nil
				}
			},
			wantSARCreation: []*authzv1.SubjectAccessReview{
				{
					Spec: authzv1.SubjectAccessReviewSpec{
						User:   "user-1",
						Groups: []string{"group-1", "group-2"},
						Extra: map[string]authzv1.ExtraValue{
							"extra": []string{"1", "2"},
						},
						UID: "uid-1",

						ResourceAttributes: &authzv1.ResourceAttributes{
							Group:     "cert-manager.io",
							Resource:  "signers",
							Verb:      "reference",
							Namespace: "hello",
							Name:      "world",
							Version:   "*",
						},
					},
				},
				{
					Spec: authzv1.SubjectAccessReviewSpec{
						User:   "user-1",
						Groups: []string{"group-1", "group-2"},
						Extra: map[string]authzv1.ExtraValue{
							"extra": []string{"1", "2"},
						},
						UID: "uid-1",

						ResourceAttributes: &authzv1.ResourceAttributes{
							Group:     "cert-manager.io",
							Resource:  "signers",
							Verb:      "reference",
							Namespace: "hello",
							Name:      "*",
							Version:   "*",
						},
					},
				},
			},
			existingIssuer: gen.Issuer("world", gen.SetIssuerNamespace("hello"),
				gen.SetIssuerCA(cmapi.CAIssuer{
					SecretName: "tls",
				}),
			),
			wantEvent: "Warning DeniedReference Requester may not reference Namespaced Issuer hello/world",
			wantConditions: []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:    certificatesv1.CertificateApproved,
					Status:  corev1.ConditionTrue,
					Reason:  "ApprovedReason",
					Message: "Approved message",
				},
				{
					Type:               certificatesv1.CertificateFailed,
					Status:             corev1.ConditionTrue,
					Reason:             "DeniedReference",
					Message:            "Requester may not reference Namespaced Issuer hello/world",
					LastTransitionTime: metaFixedClockStart,
					LastUpdateTime:     metaFixedClockStart,
				},
			},
		},
		"if CertificateSigningRequest references a issuers signer but the Issuer is not ready, fire event not Ready": {
			signerType: apiutil.IssuerCA,
			existingCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/hello.world"),
				gen.SetCertificateSigningRequestUsername("user-1"),
				gen.SetCertificateSigningRequestGroups([]string{"group-1", "group-2"}),
				gen.SetCertificateSigningRequestUID("uid-1"),
				gen.SetCertificateSigningRequestExtra(map[string]certificatesv1.ExtraValue{
					"extra": []string{"1", "2"},
				}),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:    certificatesv1.CertificateApproved,
					Status:  corev1.ConditionTrue,
					Reason:  "ApprovedReason",
					Message: "Approved message",
				}),
			),
			signerImpl:  signerExpectNoCall,
			sarReaction: sarReactionAllow,
			wantSARCreation: []*authzv1.SubjectAccessReview{
				{
					Spec: authzv1.SubjectAccessReviewSpec{
						User:   "user-1",
						Groups: []string{"group-1", "group-2"},
						Extra: map[string]authzv1.ExtraValue{
							"extra": []string{"1", "2"},
						},
						UID: "uid-1",

						ResourceAttributes: &authzv1.ResourceAttributes{
							Group:     "cert-manager.io",
							Resource:  "signers",
							Verb:      "reference",
							Namespace: "hello",
							Name:      "world",
							Version:   "*",
						},
					},
				},
			},
			wantEvent: "Warning IssuerNotReady Referenced Issuer hello/world does not have a Ready status condition",
			existingIssuer: gen.Issuer("world", gen.SetIssuerNamespace("hello"),
				gen.SetIssuerCA(cmapi.CAIssuer{
					SecretName: "tls",
				}),
			),
		},
		"if CertificateSigningRequest called invoked sign but it errors, should return error": {
			signerType: apiutil.IssuerCA,
			existingCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/hello.world"),
				gen.SetCertificateSigningRequestUsername("user-1"),
				gen.SetCertificateSigningRequestGroups([]string{"group-1", "group-2"}),
				gen.SetCertificateSigningRequestUID("uid-1"),
				gen.SetCertificateSigningRequestExtra(map[string]certificatesv1.ExtraValue{
					"extra": []string{"1", "2"},
				}),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:    certificatesv1.CertificateApproved,
					Status:  corev1.ConditionTrue,
					Reason:  "ApprovedReason",
					Message: "Approved message",
				}),
			),
			signerImpl: func(t *testing.T) Signer {
				return &fake.Signer{
					FakeSign: func(context.Context, *certificatesv1.CertificateSigningRequest, cmapi.GenericIssuer) error {
						return errors.New("this is a simulated error")
					},
				}
			},
			sarReaction: sarReactionAllow,
			wantSARCreation: []*authzv1.SubjectAccessReview{
				{
					Spec: authzv1.SubjectAccessReviewSpec{
						User:   "user-1",
						Groups: []string{"group-1", "group-2"},
						Extra: map[string]authzv1.ExtraValue{
							"extra": []string{"1", "2"},
						},
						UID: "uid-1",

						ResourceAttributes: &authzv1.ResourceAttributes{
							Group:     "cert-manager.io",
							Resource:  "signers",
							Verb:      "reference",
							Namespace: "hello",
							Name:      "world",
							Version:   "*",
						},
					},
				},
			},
			existingIssuer: gen.Issuer("world", gen.SetIssuerNamespace("hello"),
				gen.SetIssuerCA(cmapi.CAIssuer{
					SecretName: "tls",
				}),
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:    cmapi.IssuerConditionReady,
					Status:  cmmeta.ConditionTrue,
					Reason:  "IssuerReady",
					Message: "Issuer ready message",
				}),
			),
			wantErr: true,
		},
		"if CertificateSigningRequest called invoked sign and doesn't error, should return no error": {
			signerType: apiutil.IssuerCA,
			existingCSR: gen.CertificateSigningRequest("csr-1",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/hello.world"),
				gen.SetCertificateSigningRequestUsername("user-1"),
				gen.SetCertificateSigningRequestGroups([]string{"group-1", "group-2"}),
				gen.SetCertificateSigningRequestUID("uid-1"),
				gen.SetCertificateSigningRequestExtra(map[string]certificatesv1.ExtraValue{
					"extra": []string{"1", "2"},
				}),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type:    certificatesv1.CertificateApproved,
					Status:  corev1.ConditionTrue,
					Reason:  "ApprovedReason",
					Message: "Approved message",
				}),
			),
			signerImpl: func(t *testing.T) Signer {
				return &fake.Signer{
					FakeSign: func(context.Context, *certificatesv1.CertificateSigningRequest, cmapi.GenericIssuer) error {
						return nil
					},
				}
			},
			sarReaction: sarReactionAllow,
			wantSARCreation: []*authzv1.SubjectAccessReview{
				{
					Spec: authzv1.SubjectAccessReviewSpec{
						User:   "user-1",
						Groups: []string{"group-1", "group-2"},
						Extra: map[string]authzv1.ExtraValue{
							"extra": []string{"1", "2"},
						},
						UID: "uid-1",

						ResourceAttributes: &authzv1.ResourceAttributes{
							Group:     "cert-manager.io",
							Resource:  "signers",
							Verb:      "reference",
							Namespace: "hello",
							Name:      "world",
							Version:   "*",
						},
					},
				},
			},
			existingIssuer: gen.Issuer("world", gen.SetIssuerNamespace("hello"),
				gen.SetIssuerCA(cmapi.CAIssuer{
					SecretName: "tls",
				}),
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:    cmapi.IssuerConditionReady,
					Status:  cmmeta.ConditionTrue,
					Reason:  "IssuerReady",
					Message: "Issuer ready message",
				}),
			),
			wantErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			util.Clock = fixedClock
			builder := &testpkg.Builder{
				T:     t,
				Clock: fixedClock,
			}
			if test.existingIssuer != nil {
				builder.CertManagerObjects = append(builder.CertManagerObjects, test.existingIssuer)
			}
			if test.existingCSR != nil {
				builder.KubeObjects = append(builder.KubeObjects, test.existingCSR)
			}

			for i := range test.wantSARCreation {
				builder.ExpectedActions = append(builder.ExpectedActions,
					testpkg.NewAction(coretesting.NewCreateAction(
						authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews"),
						"",
						test.wantSARCreation[i],
					)),
				)
			}

			builder.Init()

			builder.FakeKubeClient().PrependReactor("create", "*", func(action coretesting.Action) (bool, runtime.Object, error) {
				if action.GetResource() != authzv1.SchemeGroupVersion.WithResource("subjectaccessreviews") {
					return false, nil, nil
				}
				return test.sarReaction(t)(action)
			})

			controller := New(test.signerType, func(*controller.Context) Signer { return test.signerImpl(t) })
			_, _, err := controller.Register(builder.Context)
			if err != nil {
				t.Fatal(err)
			}

			if test.wantConditions != nil {
				if test.existingCSR == nil {
					t.Fatal("cannot expect an Update operation if test.existingCSR is nil")
				}
				expectedCSR := test.existingCSR.DeepCopy()
				expectedCSR.Status.Conditions = test.wantConditions
				builder.ExpectedActions = append(builder.ExpectedActions,
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"),
						"status",
						"",
						expectedCSR,
					)),
				)
			}
			if test.wantEvent != "" {
				builder.ExpectedEvents = []string{test.wantEvent}
			}

			builder.Start()
			defer builder.Stop()

			key := test.key
			if key == (types.NamespacedName{}) && test.existingCSR != nil {
				key = types.NamespacedName{
					Name:      test.existingCSR.Name,
					Namespace: test.existingCSR.Namespace,
				}
			}

			gotErr := controller.ProcessItem(context.Background(), key)
			if test.wantErr != (gotErr != nil) {
				t.Errorf("got unexpected error, exp=%t got=%v",
					test.wantErr, gotErr)
			}

			builder.CheckAndFinish()
		})
	}
}
