/*
Copyright 2022 The cert-manager Authors.

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

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/fake"
	csrutil "github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func TestController_Sync(t *testing.T) {
	metaFixedTime := metav1.NewTime(fixedClockStart)
	// This Clock is used to get values for last transition time and last
	// update time when a condition is set on a CertificateSigningRequest.
	csrutil.Clock = fixedClock

	tests := map[string]testT{
		"malformed signer name": {
			builder: &testpkg.Builder{},
			csr: gen.CertificateSigningRequest("test",
				gen.SetCertificateSigningRequestSignerName("%698~1")),
		},
		"signer group is not cert-manager.io": {
			builder: &testpkg.Builder{},
			csr: gen.CertificateSigningRequest("test",
				gen.SetCertificateSigningRequestSignerName("issuers.foo.io/foo-issuer")),
		},
		"CertificateSigningRequest has failed": {
			builder: &testpkg.Builder{},
			csr: gen.CertificateSigningRequest("test",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/foo-issuer"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type: certificatesv1.CertificateFailed,
				})),
		},
		"CertificateSigningRequest has been denied": {
			builder: &testpkg.Builder{},
			csr: gen.CertificateSigningRequest("test",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/foo-issuer"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type: certificatesv1.CertificateDenied,
				})),
		},
		"CertificateSigningRequest has not yet been approved": {
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					"Normal WaitingApproval Waiting for the Approved condition before issuing",
				},
			},
			csr: gen.CertificateSigningRequest("test",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/foo-issuer")),
		},
		"Certificate has already been issued": {
			builder: &testpkg.Builder{},
			csr: gen.CertificateSigningRequest("test",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/foo-issuer"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type: certificatesv1.CertificateApproved,
				}),
				gen.SetCertificateSigningRequestCertificate([]byte("test"))),
		},
		"Signer is not Issuer or ClusterIssuer": {
			builder: &testpkg.Builder{},
			csr: gen.CertificateSigningRequest("test",
				gen.SetCertificateSigningRequestSignerName("foo.cert-manager.io/foo-issuer"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type: certificatesv1.CertificateApproved,
				})),
		},
		"Issuer is not found": {
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					"Warning IssuerNotFound Referenced Issuer /foo-issuer not found",
				},
			},
			csr: gen.CertificateSigningRequest("test",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/foo-issuer"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type: certificatesv1.CertificateApproved,
				})),
		},
		"Issuer is not one of cert-manager issuer types": {
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.Issuer("foo-issuer", gen.SetIssuerNamespace("default")),
				},
				ExpectedEvents: []string{
					"Warning IssuerTypeMissing Referenced Issuer default/foo-issuer is missing type",
				},
			},
			csr: gen.CertificateSigningRequest("test",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/default.foo-issuer"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type: certificatesv1.CertificateApproved,
				})),
		},
		// The controller is initialized with self-signed issuer type
		"Issuer is not this controller's issuer type": {
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.Issuer("foo-issuer", gen.SetIssuerNamespace("default"),
						gen.SetIssuerCA(cmapi.CAIssuer{})),
				},
			},
			csr: gen.CertificateSigningRequest("test",
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/default.foo-issuer"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type: certificatesv1.CertificateApproved,
				})),
		},
		"Duration annotation has been provided, but is invalid": {
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.ClusterIssuer("foo-issuer",
						gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{})),
				},
				ExpectedEvents: []string{
					"Warning ErrorParseDuration Failed to parse requested duration: failed to parse requested duration on annotation \"experimental.cert-manager.io/request-duration\": time: invalid duration \"foo\"",
				},

				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"),
						"status",
						"",
						gen.CertificateSigningRequest("test",
							gen.SetCertificateSigningRequestSignerName("clusterissuers.cert-manager.io/foo-issuer"),
							gen.SetCertificateSigningRequestDuration("foo"),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type: certificatesv1.CertificateApproved,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "ErrorParseDuration",
								Message:            `Failed to parse requested duration: failed to parse requested duration on annotation "experimental.cert-manager.io/request-duration": time: invalid duration "foo"`,
								LastTransitionTime: metaFixedTime,
								LastUpdateTime:     metaFixedTime,
							})),
					)),
				},
			},
			csr: gen.CertificateSigningRequest("test",
				gen.SetCertificateSigningRequestSignerName("clusterissuers.cert-manager.io/foo-issuer"),
				gen.SetCertificateSigningRequestDuration("foo"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type: certificatesv1.CertificateApproved,
				})),
		},
		"Duration annotation has been provided with a value less than 600s": {
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.ClusterIssuer("foo-issuer",
						gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{})),
				},
				ExpectedEvents: []string{
					"Warning InvalidDuration CertificateSigningRequest minimum allowed duration is 10m0s, requested 9m59s",
				},

				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
						certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"),
						"status",
						"",
						gen.CertificateSigningRequest("test",
							gen.SetCertificateSigningRequestSignerName("clusterissuers.cert-manager.io/foo-issuer"),
							gen.SetCertificateSigningRequestDuration("599s"),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type: certificatesv1.CertificateApproved,
							}),
							gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
								Type:               certificatesv1.CertificateFailed,
								Status:             corev1.ConditionTrue,
								Reason:             "InvalidDuration",
								Message:            `CertificateSigningRequest minimum allowed duration is 10m0s, requested 9m59s`,
								LastTransitionTime: metaFixedTime,
								LastUpdateTime:     metaFixedTime,
							})),
					)),
				},
			},
			csr: gen.CertificateSigningRequest("test",
				gen.SetCertificateSigningRequestSignerName("clusterissuers.cert-manager.io/foo-issuer"),
				gen.SetCertificateSigningRequestDuration("599s"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type: certificatesv1.CertificateApproved,
				})),
		},
		// TODO (irbekrm) Test the scenario where the user is not allowed to reference Issuer
		// Perhaps restructure and use fake SubjectAccessReview https://github.com/kubernetes/client-go/blob/master/kubernetes/typed/authorization/v1/fake/fake_subjectaccessreview.go
		"Referenced ClusterIssuer is not ready": {
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.ClusterIssuer("foo-issuer",
						gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{})),
				},
				ExpectedEvents: []string{
					"Warning IssuerNotReady Referenced ClusterIssuer /foo-issuer does not have a Ready status condition",
				},
			},
			csr: gen.CertificateSigningRequest("test",
				gen.SetCertificateSigningRequestSignerName("clusterissuers.cert-manager.io/foo-issuer"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type: certificatesv1.CertificateApproved,
				})),
		},
		"Signing fails": {
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.ClusterIssuer("foo-issuer",
						gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:   cmapi.IssuerConditionReady,
							Status: cmmeta.ConditionTrue,
						})),
				},
			},
			csr: gen.CertificateSigningRequest("test",
				gen.SetCertificateSigningRequestSignerName("clusterissuers.cert-manager.io/foo-issuer"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type: certificatesv1.CertificateApproved,
				})),
			signerImpl: &fake.Signer{
				FakeSign: func(context.Context, *certificatesv1.CertificateSigningRequest, cmapi.GenericIssuer) error {
					return errors.New("some error")
				},
			},
			wantErr: true,
		},
		"Signing succeeds": {
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.ClusterIssuer("foo-issuer",
						gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:   cmapi.IssuerConditionReady,
							Status: cmmeta.ConditionTrue,
						})),
				},
			},
			csr: gen.CertificateSigningRequest("test",
				gen.SetCertificateSigningRequestSignerName("clusterissuers.cert-manager.io/foo-issuer"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type: certificatesv1.CertificateApproved,
				})),
			signerImpl: &fake.Signer{
				FakeSign: func(context.Context, *certificatesv1.CertificateSigningRequest, cmapi.GenericIssuer) error {
					return nil
				},
			},
		},
		"Signing succeeds with a valid duration annotation": {
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.ClusterIssuer("foo-issuer",
						gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
						gen.AddIssuerCondition(cmapi.IssuerCondition{
							Type:   cmapi.IssuerConditionReady,
							Status: cmmeta.ConditionTrue,
						})),
				},
			},
			csr: gen.CertificateSigningRequest("test",
				gen.SetCertificateSigningRequestSignerName("clusterissuers.cert-manager.io/foo-issuer"),
				gen.SetCertificateSigningRequestDuration("600s"),
				gen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
					Type: certificatesv1.CertificateApproved,
				})),
			signerImpl: &fake.Signer{
				FakeSign: func(context.Context, *certificatesv1.CertificateSigningRequest, cmapi.GenericIssuer) error {
					return nil
				},
			},
		},
	}
	for name, scenario := range tests {
		t.Run(name, func(t *testing.T) {
			if scenario.csr != nil {
				scenario.builder.KubeObjects = append(scenario.builder.KubeObjects, scenario.csr)
			}
			fixedClock.SetTime(fixedClockStart)
			scenario.builder.Clock = fixedClock
			scenario.builder.T = t
			scenario.builder.Init()

			defer scenario.builder.Stop()

			if scenario.signerImpl == nil {
				scenario.signerImpl = &fake.Signer{
					FakeSign: func(context.Context, *certificatesv1.CertificateSigningRequest, cmapi.GenericIssuer) error {
						return errors.New("unexpected sign call")
					},
				}
			}

			c := New(util.IssuerSelfSigned, func(*controller.Context) Signer { return scenario.signerImpl })
			if _, _, err := c.Register(scenario.builder.Context); err != nil {
				t.Fatal(err)
			}

			scenario.builder.Start()

			err := c.Sync(context.Background(), scenario.csr)
			if (err == nil) == scenario.wantErr {
				t.Errorf("expected error: %v, but got: %v", scenario.wantErr, err)
			}
			scenario.builder.CheckAndFinish(err)
		})
	}
}

type testT struct {
	builder    *testpkg.Builder
	csr        *certificatesv1.CertificateSigningRequest
	signerImpl Signer
	wantErr    bool
}
