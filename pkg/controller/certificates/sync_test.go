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
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	_ "github.com/jetstack/cert-manager/pkg/issuer/selfsigned"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func TestSyncHappyPath(t *testing.T) {
	// nowTime := time.Now()
	// nowMetaTime := metav1.NewTime(nowTime)
	// fixedClock := fakeclock.NewFakeClock(nowTime)

	tests := map[string]controllerFixture{
		"nothing": {
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
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.Certificate("test")},
				ExpectedActions: []testpkg.Action{
					testpkg.NewCustomMatch(coretesting.NewCreateAction(corev1.SchemeGroupVersion.WithResource("secrets"), gen.DefaultTestNamespace, nil),
						func(exp, _ coretesting.Action) bool {
							return false
						}),
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
