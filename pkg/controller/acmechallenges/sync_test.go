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

package acmechallenges

import (
	"context"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	acmecl "github.com/jetstack/cert-manager/pkg/acme/client"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns"
	"github.com/jetstack/cert-manager/test/unit/gen"
	acmeapi "github.com/jetstack/cert-manager/third_party/crypto/acme"
)

// Present the challenge value with the given solver.
func (f *fakeSolver) Present(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	return f.fakePresent(ctx, issuer, ch)
}

// Check should return Error only if propagation check cannot be performed.
// It MUST return `false, nil` if can contact all relevant services and all is
// doing is waiting for propagation
func (f *fakeSolver) Check(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	return f.fakeCheck(ctx, issuer, ch)
}

// CleanUp will remove challenge records for a given solver.
// This may involve deleting resources in the Kubernetes API Server, or
// communicating with other external components (e.g. DNS providers).
func (f *fakeSolver) CleanUp(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	return f.fakeCleanUp(ctx, issuer, ch)
}

type fakeSolver struct {
	fakePresent func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error
	fakeCheck   func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error
	fakeCleanUp func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error
}

func TestSyncHappyPath(t *testing.T) {
	testIssuerHTTP01Enabled := &v1alpha1.Issuer{
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				ACME: &v1alpha1.ACMEIssuer{
					HTTP01: &v1alpha1.ACMEIssuerHTTP01Config{},
				},
			},
		},
	}

	tests := map[string]controllerFixture{
		"update status if state is unknown": {
			Issuer: testIssuerHTTP01Enabled,
			Challenge: gen.Challenge("testchal",
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
			),
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.Challenge("testchal",
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
				)},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), gen.DefaultTestNamespace,
						gen.Challenge("testchal",
							gen.SetChallengeProcessing(true),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeState(v1alpha1.Pending),
						))),
				},
			},
			Client: &acmecl.FakeACME{
				FakeGetChallenge: func(ctx context.Context, url string) (*acmeapi.Challenge, error) {
					return &acmeapi.Challenge{Status: acmeapi.StatusPending}, nil
				},
			},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
		"call Present and update challenge status to presented": {
			Issuer: testIssuerHTTP01Enabled,
			Challenge: gen.Challenge("testchal",
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeState(v1alpha1.Pending),
				gen.SetChallengeType("http-01"),
			),
			HTTP01: &fakeSolver{
				fakePresent: func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
					return nil
				},
				fakeCheck: func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
					return fmt.Errorf("some error")
				},
			},
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.Challenge("testchal",
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeState(v1alpha1.Pending),
					gen.SetChallengeType("http-01"),
				)},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), gen.DefaultTestNamespace,
						gen.Challenge("testchal",
							gen.SetChallengeProcessing(true),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeState(v1alpha1.Pending),
							gen.SetChallengePresented(true),
							gen.SetChallengeType("http-01"),
							gen.SetChallengeReason("Waiting for http-01 challenge propagation: some error"),
						))),
				},
			},
			Client: &acmecl.FakeACME{},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
		"accept the challenge if the self check is passing": {
			Issuer: testIssuerHTTP01Enabled,
			Challenge: gen.Challenge("testchal",
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeState(v1alpha1.Pending),
				gen.SetChallengeType("http-01"),
				gen.SetChallengePresented(true),
			),
			HTTP01: &fakeSolver{
				fakeCheck: func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
					return nil
				},
				fakeCleanUp: func(context.Context, v1alpha1.GenericIssuer, *v1alpha1.Challenge) error {
					return nil
				},
			},
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.Challenge("testchal",
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeState(v1alpha1.Pending),
					gen.SetChallengeType("http-01"),
					gen.SetChallengePresented(true),
				)},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), gen.DefaultTestNamespace,
						gen.Challenge("testchal",
							gen.SetChallengeProcessing(true),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeState(v1alpha1.Valid),
							gen.SetChallengeType("http-01"),
							gen.SetChallengePresented(true),
							gen.SetChallengeReason("Successfully authorized domain"),
						))),
				},
			},
			Client: &acmecl.FakeACME{
				FakeAcceptChallenge: func(context.Context, *acmeapi.Challenge) (*acmeapi.Challenge, error) {
					// return something other than valid here so we can verify that
					// the challenge.status.state is set to the *authorizations*
					// status and not the challenges
					return &acmeapi.Challenge{Status: acmeapi.StatusPending}, nil
				},
				FakeWaitAuthorization: func(context.Context, string) (*acmeapi.Authorization, error) {
					return &acmeapi.Authorization{Status: acmeapi.StatusValid}, nil
				},
			},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
		"mark certificate as failed if accepting the authorization fails": {
			Issuer: testIssuerHTTP01Enabled,
			Challenge: gen.Challenge("testchal",
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeState(v1alpha1.Pending),
				gen.SetChallengeType("http-01"),
				gen.SetChallengePresented(true),
			),
			HTTP01: &fakeSolver{
				fakeCheck: func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
					return nil
				},
				fakeCleanUp: func(context.Context, v1alpha1.GenericIssuer, *v1alpha1.Challenge) error {
					return nil
				},
			},
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.Challenge("testchal",
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeState(v1alpha1.Pending),
					gen.SetChallengeType("http-01"),
					gen.SetChallengePresented(true),
				)},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), gen.DefaultTestNamespace,
						gen.Challenge("testchal",
							gen.SetChallengeProcessing(true),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeState(v1alpha1.Invalid),
							gen.SetChallengeType("http-01"),
							gen.SetChallengePresented(true),
							gen.SetChallengeReason("Error accepting authorization: acme: authorization for identifier example.com is invalid"),
						))),
				},
			},
			Client: &acmecl.FakeACME{
				FakeAcceptChallenge: func(context.Context, *acmeapi.Challenge) (*acmeapi.Challenge, error) {
					// return something other than invalid here so we can verify that
					// the challenge.status.state is set to the *authorizations*
					// status and not the challenges
					return &acmeapi.Challenge{Status: acmeapi.StatusPending}, nil
				},
				FakeWaitAuthorization: func(context.Context, string) (*acmeapi.Authorization, error) {
					return nil, acmeapi.AuthorizationError{
						Authorization: &acmeapi.Authorization{
							Status: acmeapi.StatusInvalid,
							Identifier: acmeapi.AuthzID{
								Value: "example.com",
							},
						},
					}
				},
			},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
		"mark the challenge as not processing if it is already valid": {
			Issuer: testIssuerHTTP01Enabled,
			Challenge: gen.Challenge("testchal",
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeState(v1alpha1.Valid),
				gen.SetChallengeType("http-01"),
				gen.SetChallengePresented(true),
			),
			HTTP01: &fakeSolver{
				fakeCleanUp: func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
					return nil
				},
			},
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.Challenge("testchal",
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeState(v1alpha1.Valid),
					gen.SetChallengeType("http-01"),
					gen.SetChallengePresented(true),
				)},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), gen.DefaultTestNamespace,
						gen.Challenge("testchal",
							gen.SetChallengeProcessing(false),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeState(v1alpha1.Valid),
							gen.SetChallengeType("http-01"),
							gen.SetChallengePresented(false),
						))),
				},
			},
		},
		"mark the challenge as not processing if it is already failed": {
			Issuer: testIssuerHTTP01Enabled,
			Challenge: gen.Challenge("testchal",
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeState(v1alpha1.Invalid),
				gen.SetChallengeType("http-01"),
				gen.SetChallengePresented(true),
			),
			HTTP01: &fakeSolver{
				fakeCleanUp: func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
					return nil
				},
			},
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.Challenge("testchal",
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeState(v1alpha1.Invalid),
					gen.SetChallengeType("http-01"),
					gen.SetChallengePresented(true),
				)},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), gen.DefaultTestNamespace,
						gen.Challenge("testchal",
							gen.SetChallengeProcessing(false),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeState(v1alpha1.Invalid),
							gen.SetChallengeType("http-01"),
							gen.SetChallengePresented(false),
						))),
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.Builder == nil {
				test.Builder = &testpkg.Builder{}
			}
			// Don't initialise webhook based DNS solvers during tests as we do
			// not have a valid RESTConfig that can be used in the Initialize
			// functions.
			dns.WebhookSolvers = nil
			test.Setup(t)
			chalCopy := test.Challenge.DeepCopy()
			err := test.Controller.Sync(test.Ctx, chalCopy)
			if err != nil && !test.Err {
				t.Errorf("Expected function to not error, but got: %v", err)
			}
			if err == nil && test.Err {
				t.Errorf("Expected function to get an error, but got: %v", err)
			}
			test.Finish(t, chalCopy, err)
		})
	}
}
