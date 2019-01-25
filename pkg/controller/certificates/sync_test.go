/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package certificates

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	clock "k8s.io/utils/clock/testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/issuer/fake"
	_ "github.com/jetstack/cert-manager/pkg/issuer/selfsigned"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func TestSync(t *testing.T) {
	nowTime := time.Now()
	nowMetaTime := metav1.NewTime(nowTime)
	fixedClock := clock.NewFakeClock(nowTime)

	tests := map[string]controllerFixture{
		"should update certificate with NotExists if issuer does not return a keypair": {
			Issuer: gen.Issuer("test",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmapi.ConditionTrue,
				}),
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			Certificate: *gen.Certificate("test",
				gen.SetCertificateDNSNames("example.com"),
				gen.SetCertificateIssuer(cmapi.ObjectReference{Name: "test"}),
				gen.SetCertificateSecretName("output"),
			),
			IssuerImpl: &fake.Issuer{
				FakeIssue: func(context.Context, *cmapi.Certificate) (*issuer.IssueResponse, error) {
					return nil, nil
				},
			},
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.Certificate("test")},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						gen.DefaultTestNamespace,
						gen.Certificate("test",
							gen.SetCertificateDNSNames("example.com"),
							gen.SetCertificateIssuer(cmapi.ObjectReference{Name: "test"}),
							gen.SetCertificateSecretName("output"),
							gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
								Type:               cmapi.CertificateConditionReady,
								Status:             cmapi.ConditionFalse,
								Reason:             "NotFound",
								Message:            "Certificate does not exist",
								LastTransitionTime: nowMetaTime,
							}),
						),
					)),
				},
			},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			if test.Builder == nil {
				test.Builder = &testpkg.Builder{}
			}
			test.Clock = fixedClock
			test.Setup(t)
			crtCopy := test.Certificate.DeepCopy()
			err := test.Controller.Sync(test.Ctx, crtCopy)
			if err != nil && !test.Err {
				t.Errorf("Expected function to not error, but got: %v", err)
			}
			if err == nil && test.Err {
				t.Errorf("Expected function to get an error, but got: %v", err)
			}
			test.Finish(t, crtCopy, err)
		})
	}
}
