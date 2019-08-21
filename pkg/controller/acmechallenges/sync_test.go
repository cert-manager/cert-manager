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
	acmefake "github.com/jetstack/cert-manager/pkg/acme/fake"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer"
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

type testT struct {
	challenge  *v1alpha1.Challenge
	builder    *testpkg.Builder
	httpSolver *fakeSolver
	dnsSolver  *fakeSolver
	expectErr  bool
	acmeClient *acmecl.FakeACME
}

func TestSyncHappyPath(t *testing.T) {
	testIssuerHTTP01Enabled := gen.Issuer("testissuer", gen.SetIssuerACME(v1alpha1.ACMEIssuer{
		HTTP01: &v1alpha1.ACMEIssuerHTTP01Config{},
	}))
	baseChallenge := gen.Challenge("testchal",
		gen.SetChallengeIssuer(v1alpha1.ObjectReference{
			Name: "testissuer",
		}),
	)

	tests := map[string]testT{
		"update status if state is unknown": {
			challenge: gen.ChallengeFrom(baseChallenge,
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.ChallengeFrom(baseChallenge,
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
				), testIssuerHTTP01Enabled},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), gen.DefaultTestNamespace,
						gen.ChallengeFrom(baseChallenge,
							gen.SetChallengeProcessing(true),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeState(v1alpha1.Pending),
						))),
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetChallenge: func(ctx context.Context, url string) (*acmeapi.Challenge, error) {
					return &acmeapi.Challenge{Status: acmeapi.StatusPending}, nil
				},
			},
		},
		"call Present and update challenge status to presented": {
			challenge: gen.ChallengeFrom(baseChallenge,
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeState(v1alpha1.Pending),
				gen.SetChallengeType("http-01"),
			),
			httpSolver: &fakeSolver{
				fakePresent: func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
					return nil
				},
				fakeCheck: func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
					return fmt.Errorf("some error")
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.ChallengeFrom(baseChallenge,
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeState(v1alpha1.Pending),
					gen.SetChallengeType("http-01"),
				), testIssuerHTTP01Enabled},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), gen.DefaultTestNamespace,
						gen.ChallengeFrom(baseChallenge,
							gen.SetChallengeProcessing(true),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeState(v1alpha1.Pending),
							gen.SetChallengePresented(true),
							gen.SetChallengeType("http-01"),
							gen.SetChallengeReason("Waiting for http-01 challenge propagation: some error"),
						))),
				},
				ExpectedEvents: []string{
					"Normal Presented Presented challenge using http-01 challenge mechanism",
				},
			},
		},
		"accept the challenge if the self check is passing": {
			challenge: gen.ChallengeFrom(baseChallenge,
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeDNSName("test.com"),
				gen.SetChallengeState(v1alpha1.Pending),
				gen.SetChallengeType("http-01"),
				gen.SetChallengePresented(true),
			),
			httpSolver: &fakeSolver{
				fakeCheck: func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
					return nil
				},
				fakeCleanUp: func(context.Context, v1alpha1.GenericIssuer, *v1alpha1.Challenge) error {
					return nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.ChallengeFrom(baseChallenge,
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeDNSName("test.com"),
					gen.SetChallengeState(v1alpha1.Pending),
					gen.SetChallengeType("http-01"),
					gen.SetChallengePresented(true),
				), testIssuerHTTP01Enabled},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), gen.DefaultTestNamespace,
						gen.ChallengeFrom(baseChallenge,
							gen.SetChallengeProcessing(true),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeDNSName("test.com"),
							gen.SetChallengeState(v1alpha1.Valid),
							gen.SetChallengeType("http-01"),
							gen.SetChallengePresented(true),
							gen.SetChallengeReason("Successfully authorized domain"),
						))),
				},
				ExpectedEvents: []string{
					`Normal DomainVerified Domain "test.com" verified with "http-01" validation`,
				},
			},
			acmeClient: &acmecl.FakeACME{
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
		},
		"mark certificate as failed if accepting the authorization fails": {
			challenge: gen.ChallengeFrom(baseChallenge,
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeState(v1alpha1.Pending),
				gen.SetChallengeType("http-01"),
				gen.SetChallengePresented(true),
			),
			httpSolver: &fakeSolver{
				fakeCheck: func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
					return nil
				},
				fakeCleanUp: func(context.Context, v1alpha1.GenericIssuer, *v1alpha1.Challenge) error {
					return nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.ChallengeFrom(baseChallenge,
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeState(v1alpha1.Pending),
					gen.SetChallengeType("http-01"),
					gen.SetChallengePresented(true),
				), testIssuerHTTP01Enabled},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), gen.DefaultTestNamespace,
						gen.ChallengeFrom(baseChallenge,
							gen.SetChallengeProcessing(true),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeState(v1alpha1.Invalid),
							gen.SetChallengeType("http-01"),
							gen.SetChallengePresented(true),
							gen.SetChallengeReason("Error accepting authorization: acme: authorization for identifier example.com is invalid"),
						))),
				},
				ExpectedEvents: []string{
					"Warning Failed Accepting challenge authorization failed: acme: authorization for identifier example.com is invalid",
				},
			},
			acmeClient: &acmecl.FakeACME{
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
		},
		"mark the challenge as not processing if it is already valid": {
			challenge: gen.ChallengeFrom(baseChallenge,
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeState(v1alpha1.Valid),
				gen.SetChallengeType("http-01"),
				gen.SetChallengePresented(true),
			),
			httpSolver: &fakeSolver{
				fakeCleanUp: func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
					return nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.ChallengeFrom(baseChallenge,
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeState(v1alpha1.Valid),
					gen.SetChallengeType("http-01"),
					gen.SetChallengePresented(true),
				), testIssuerHTTP01Enabled},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), gen.DefaultTestNamespace,
						gen.ChallengeFrom(baseChallenge,
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
			challenge: gen.ChallengeFrom(baseChallenge,
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeState(v1alpha1.Invalid),
				gen.SetChallengeType("http-01"),
				gen.SetChallengePresented(true),
			),
			httpSolver: &fakeSolver{
				fakeCleanUp: func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
					return nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.ChallengeFrom(baseChallenge,
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeState(v1alpha1.Invalid),
					gen.SetChallengeType("http-01"),
					gen.SetChallengePresented(true),
				), testIssuerHTTP01Enabled},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), gen.DefaultTestNamespace,
						gen.ChallengeFrom(baseChallenge,
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
			runTest(t, test)
		})
	}
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Init()
	defer test.builder.Stop()

	c := &controller{}
	c.Register(test.builder.Context)
	c.helper = issuer.NewHelper(
		test.builder.SharedInformerFactory.Certmanager().V1alpha1().Issuers().Lister(),
		test.builder.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers().Lister(),
	)
	c.acmeHelper = &acmefake.Helper{
		ClientForIssuerFunc: func(iss v1alpha1.GenericIssuer) (acmecl.Interface, error) {
			return test.acmeClient, nil
		},
	}
	c.httpSolver = test.httpSolver
	c.dnsSolver = test.dnsSolver
	test.builder.Start()

	err := c.Sync(context.Background(), test.challenge)
	if err != nil && !test.expectErr {
		t.Errorf("Expected function to not error, but got: %v", err)
	}
	if err == nil && test.expectErr {
		t.Errorf("Expected function to get an error, but got: %v", err)
	}

	test.builder.CheckAndFinish(err)
}
