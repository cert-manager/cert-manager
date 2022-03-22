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
	"k8s.io/apimachinery/pkg/runtime"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/fake"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = fakeclock.NewFakeClock(fixedClockStart)
)

func TestController_Sync(t *testing.T) {
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
	}
	for name, scenario := range tests {
		t.Run(name, func(t *testing.T) {
			fixedClock.SetTime(fixedClockStart)
			runTest(t, scenario)
		})
	}
}

type testT struct {
	builder    *testpkg.Builder
	csr        *certificatesv1.CertificateSigningRequest
	signerImpl Signer
	wantErr    bool
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Clock = fixedClock
	test.builder.Init()

	defer test.builder.Stop()

	if test.signerImpl == nil {
		test.signerImpl = &fake.Signer{
			FakeSign: func(context.Context, *certificatesv1.CertificateSigningRequest, cmapi.GenericIssuer) error {
				return errors.New("unexpected sign call")
			},
		}
	}

	c := New(util.IssuerSelfSigned, func(*controller.Context) Signer { return test.signerImpl })
	c.Register(test.builder.Context)

	test.builder.Start()

	err := c.Sync(context.Background(), test.csr)
	if (err == nil) == test.wantErr {
		t.Errorf("expected error: %v, but got: %v", test.wantErr, err)
	}
	test.builder.CheckAndFinish(err)
}
