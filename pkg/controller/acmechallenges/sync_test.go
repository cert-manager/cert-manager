/*
Copyright 2020 The cert-manager Authors.

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
	"errors"
	"fmt"
	"testing"

	acmeapi "golang.org/x/crypto/acme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	accountstest "github.com/cert-manager/cert-manager/pkg/acme/accounts/test"
	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

// Present the challenge value with the given solver.
func (f *fakeSolver) Present(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error {
	return f.fakePresent(ctx, issuer, ch)
}

// Check should return Error only if propagation check cannot be performed.
// It MUST return `false, nil` if it can contact all relevant services and all it is
// doing is waiting for propagation
func (f *fakeSolver) Check(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error {
	return f.fakeCheck(ctx, issuer, ch)
}

// CleanUp will remove challenge records for a given solver.
// This may involve deleting resources in the Kubernetes API Server, or
// communicating with other external components (e.g. DNS providers).
func (f *fakeSolver) CleanUp(ctx context.Context, ch *cmacme.Challenge) error {
	return f.fakeCleanUp(ctx, ch)
}

type fakeSolver struct {
	fakePresent func(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error
	fakeCheck   func(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error
	fakeCleanUp func(ctx context.Context, ch *cmacme.Challenge) error
}

type testT struct {
	challenge  *cmacme.Challenge
	builder    *testpkg.Builder
	httpSolver *fakeSolver
	dnsSolver  *fakeSolver
	expectErr  bool
	acmeClient *acmecl.FakeACME
}

func testSyncHappyPathWithFinalizer(t *testing.T, finalizer string, activeFinalizer string) {
	testIssuerHTTP01Enabled := gen.Issuer("testissuer", gen.SetIssuerACME(cmacme.ACMEIssuer{
		Solvers: []cmacme.ACMEChallengeSolver{
			{
				HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
					Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
				},
			},
		},
	}))
	baseChallenge := gen.Challenge("testchal",
		gen.SetChallengeIssuer(cmmeta.ObjectReference{
			Name: "testissuer",
		}),
		gen.SetChallengeFinalizers([]string{finalizer}),
	)
	deletedChallenge := gen.ChallengeFrom(baseChallenge,
		gen.SetChallengeDeletionTimestamp(metav1.Now()))

	simulatedCleanupError := errors.New("simulated-cleanup-error")
	tests := map[string]testT{
		"cleanup if the challenge is deleted and remove the finalizer": {
			challenge: gen.ChallengeFrom(deletedChallenge,
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
			),
			httpSolver: &fakeSolver{
				fakeCleanUp: func(ctx context.Context, ch *cmacme.Challenge) error {
					return nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.ChallengeFrom(deletedChallenge,
						gen.SetChallengeProcessing(true),
						gen.SetChallengeURL("testurl"),
						gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
					),
					testIssuerHTTP01Enabled,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
						gen.DefaultTestNamespace,
						gen.ChallengeFrom(deletedChallenge,
							gen.SetChallengeProcessing(true),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
							gen.SetChallengeFinalizers([]string{}),
						))),
				},
			},
		},
		"if the challenge is deleted and the cleanup fails, set the reason (and remove the finalizer, which is a bug)": {
			challenge: gen.ChallengeFrom(deletedChallenge,
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
			),
			httpSolver: &fakeSolver{
				fakeCleanUp: func(context.Context, *cmacme.Challenge) error {
					return simulatedCleanupError
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.ChallengeFrom(deletedChallenge,
						gen.SetChallengeProcessing(true),
						gen.SetChallengeURL("testurl"),
						gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
					),
					testIssuerHTTP01Enabled,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
						gen.DefaultTestNamespace,
						gen.ChallengeFrom(deletedChallenge,
							gen.SetChallengeProcessing(true),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
							gen.SetChallengeFinalizers([]string{}),
							gen.SetChallengeReason(simulatedCleanupError.Error()),
						))),
					testpkg.NewAction(
						coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
							"status",
							gen.DefaultTestNamespace,
							gen.ChallengeFrom(deletedChallenge,
								gen.SetChallengeProcessing(true),
								gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
								gen.SetChallengeURL("testurl"),
								gen.SetChallengeFinalizers([]string{}),
								gen.SetChallengeReason(simulatedCleanupError.Error()),
							))),
				},
				ExpectedEvents: []string{
					fmt.Sprintf("Warning CleanUpError Error cleaning up challenge: %s", simulatedCleanupError),
				},
			},
		},
		"if finalizer is missing, add it": {
			challenge: gen.ChallengeFrom(baseChallenge,
				gen.SetChallengeProcessing(true),
				gen.SetChallengeFinalizers(nil),
			),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.ChallengeFrom(baseChallenge,
					gen.SetChallengeProcessing(true),
					gen.SetChallengeFinalizers(nil),
				), testIssuerHTTP01Enabled},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(
						coretesting.NewUpdateAction(
							cmacme.SchemeGroupVersion.WithResource("challenges"),
							gen.DefaultTestNamespace,
							gen.ChallengeFrom(baseChallenge,
								gen.SetChallengeProcessing(true),
								gen.SetChallengeFinalizers([]string{activeFinalizer})))),
				},
			},
			expectErr: false,
		},
		"if GetAuthorization doesn't return challenge, error": {
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
					testpkg.NewAction(
						coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
							"status",
							gen.DefaultTestNamespace,
							gen.ChallengeFrom(baseChallenge,
								gen.SetChallengeURL("testurl"),
								gen.SetChallengeProcessing(true),
								gen.SetChallengeReason("unexpected non-ACME API error: challenge was not present in authorization"),
								gen.SetChallengeState(cmacme.Errored)))),
				},
			},
			expectErr: true,
			acmeClient: &acmecl.FakeACME{
				FakeGetAuthorization: func(ctx context.Context, url string) (*acmeapi.Authorization, error) {
					return &acmeapi.Authorization{
						Challenges: []*acmeapi.Challenge{
							{URI: "foo", Status: acmeapi.StatusPending},
						},
					}, nil
				},
			},
		},
		"if GetAuthorization returns challenge ready, update ready": {
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
					testpkg.NewAction(
						coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
							"status",
							gen.DefaultTestNamespace,
							gen.ChallengeFrom(baseChallenge,
								gen.SetChallengeProcessing(true),
								gen.SetChallengeURL("testurl"),
								gen.SetChallengeState(cmacme.Ready),
							))),
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetAuthorization: func(ctx context.Context, url string) (*acmeapi.Authorization, error) {
					return &acmeapi.Authorization{
						Challenges: []*acmeapi.Challenge{
							{URI: "testurl", Status: acmeapi.StatusReady},
						},
					}, nil
				},
			},
		},
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
					testpkg.NewAction(
						coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
							"status",
							gen.DefaultTestNamespace,
							gen.ChallengeFrom(baseChallenge,
								gen.SetChallengeProcessing(true),
								gen.SetChallengeURL("testurl"),
								gen.SetChallengeState(cmacme.Pending),
							))),
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetAuthorization: func(ctx context.Context, url string) (*acmeapi.Authorization, error) {
					return &acmeapi.Authorization{
						Challenges: []*acmeapi.Challenge{
							{URI: "testurl", Status: acmeapi.StatusPending},
						},
					}, nil
				},
			},
		},
		"call Present and update challenge status to presented": {
			challenge: gen.ChallengeFrom(baseChallenge,
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeState(cmacme.Pending),
				gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
			),
			httpSolver: &fakeSolver{
				fakePresent: func(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error {
					return nil
				},
				fakeCheck: func(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error {
					return fmt.Errorf("some error")
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.ChallengeFrom(baseChallenge,
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeState(cmacme.Pending),
					gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
				), testIssuerHTTP01Enabled},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
						"status",
						gen.DefaultTestNamespace,
						gen.ChallengeFrom(baseChallenge,
							gen.SetChallengeProcessing(true),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeState(cmacme.Pending),
							gen.SetChallengePresented(true),
							gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
							gen.SetChallengeReason("Waiting for HTTP-01 challenge propagation: some error"),
						))),
				},
				ExpectedEvents: []string{
					//nolint: dupword
					"Normal Presented Presented challenge using HTTP-01 challenge mechanism",
				},
			},
		},
		"accept the challenge if the self check is passing": {
			challenge: gen.ChallengeFrom(baseChallenge,
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeDNSName("test.com"),
				gen.SetChallengeState(cmacme.Pending),
				gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
				gen.SetChallengePresented(true),
			),
			httpSolver: &fakeSolver{
				fakeCheck: func(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error {
					return nil
				},
				fakeCleanUp: func(context.Context, *cmacme.Challenge) error {
					return nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.ChallengeFrom(baseChallenge,
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeDNSName("test.com"),
					gen.SetChallengeState(cmacme.Pending),
					gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
					gen.SetChallengePresented(true),
				), testIssuerHTTP01Enabled},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
						"status",
						gen.DefaultTestNamespace,
						gen.ChallengeFrom(baseChallenge,
							gen.SetChallengeProcessing(true),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeDNSName("test.com"),
							gen.SetChallengeState(cmacme.Valid),
							gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
							gen.SetChallengePresented(true),
							gen.SetChallengeReason("Successfully authorized domain"),
						))),
				},
				ExpectedEvents: []string{
					`Normal DomainVerified Domain "test.com" verified with "HTTP-01" validation`,
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeAccept: func(context.Context, *acmeapi.Challenge) (*acmeapi.Challenge, error) {
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
				gen.SetChallengeState(cmacme.Pending),
				gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
				gen.SetChallengePresented(true),
			),
			httpSolver: &fakeSolver{
				fakeCheck: func(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error {
					return nil
				},
				fakeCleanUp: func(context.Context, *cmacme.Challenge) error {
					return nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.ChallengeFrom(baseChallenge,
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeState(cmacme.Pending),
					gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
					gen.SetChallengePresented(true),
				), testIssuerHTTP01Enabled},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
						"status",
						gen.DefaultTestNamespace,
						gen.ChallengeFrom(baseChallenge,
							gen.SetChallengeProcessing(true),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeState(cmacme.Invalid),
							gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
							gen.SetChallengePresented(true),
							gen.SetChallengeReason("Error accepting authorization: acme: authorization error for example.com: an error happened"),
						))),
				},
				ExpectedEvents: []string{
					"Warning Failed Accepting challenge authorization failed: acme: authorization error for example.com: an error happened",
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeAccept: func(context.Context, *acmeapi.Challenge) (*acmeapi.Challenge, error) {
					// return something other than invalid here so we can verify that
					// the challenge.status.state is set to the *authorizations*
					// status and not the challenges
					return &acmeapi.Challenge{Status: acmeapi.StatusPending}, nil
				},
				FakeWaitAuthorization: func(context.Context, string) (*acmeapi.Authorization, error) {
					return nil, &acmeapi.AuthorizationError{
						URI:        "http://testerroruri",
						Identifier: "example.com",
						Errors: []error{
							fmt.Errorf("an error happened"),
						},
					}
				},
			},
		},
		"correctly persist ACME authorization error details as Challenge failure reason": {
			challenge: gen.ChallengeFrom(baseChallenge,
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeState(cmacme.Pending),
				gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
				gen.SetChallengePresented(true),
			),
			httpSolver: &fakeSolver{
				fakeCheck: func(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error {
					return nil
				},
				fakeCleanUp: func(context.Context, *cmacme.Challenge) error {
					return nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.ChallengeFrom(baseChallenge,
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeState(cmacme.Pending),
					gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
					gen.SetChallengePresented(true),
				), testIssuerHTTP01Enabled},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
						"status",
						gen.DefaultTestNamespace,
						gen.ChallengeFrom(baseChallenge,
							gen.SetChallengeProcessing(true),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeState(cmacme.Invalid),
							gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
							gen.SetChallengePresented(true),
							gen.SetChallengeReason("Error accepting authorization: acme: authorization error for example.com: 400 fakeerror: this is a very detailed error"),
						))),
				},
				ExpectedEvents: []string{
					"Warning Failed Accepting challenge authorization failed: acme: authorization error for example.com: 400 fakeerror: this is a very detailed error",
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeAccept: func(context.Context, *acmeapi.Challenge) (*acmeapi.Challenge, error) {
					// return something other than invalid here so we can verify that
					// the challenge.status.state is set to the *authorizations*
					// status and not the challenges
					return &acmeapi.Challenge{Status: acmeapi.StatusPending}, nil
				},
				FakeWaitAuthorization: func(context.Context, string) (*acmeapi.Authorization, error) {
					return nil, &acmeapi.AuthorizationError{
						URI:        "http://testerroruri",
						Identifier: "example.com",
						Errors: []error{
							&acmeapi.Error{
								StatusCode:  400,
								ProblemType: "fakeerror",
								Detail:      "this is a very detailed error",
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
				gen.SetChallengeState(cmacme.Valid),
				gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
				gen.SetChallengePresented(true),
			),
			httpSolver: &fakeSolver{
				fakeCleanUp: func(context.Context, *cmacme.Challenge) error {
					return nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.ChallengeFrom(baseChallenge,
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeState(cmacme.Valid),
					gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
					gen.SetChallengePresented(true),
				), testIssuerHTTP01Enabled},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
						"status",
						gen.DefaultTestNamespace,
						gen.ChallengeFrom(baseChallenge,
							gen.SetChallengeProcessing(false),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeState(cmacme.Valid),
							gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
							gen.SetChallengePresented(false),
						))),
				},
			},
		},
		"mark the challenge as not processing if it is already failed": {
			challenge: gen.ChallengeFrom(baseChallenge,
				gen.SetChallengeProcessing(true),
				gen.SetChallengeURL("testurl"),
				gen.SetChallengeState(cmacme.Invalid),
				gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
				gen.SetChallengePresented(true),
			),
			httpSolver: &fakeSolver{
				fakeCleanUp: func(context.Context, *cmacme.Challenge) error {
					return nil
				},
			},
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{gen.ChallengeFrom(baseChallenge,
					gen.SetChallengeProcessing(true),
					gen.SetChallengeURL("testurl"),
					gen.SetChallengeState(cmacme.Invalid),
					gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
					gen.SetChallengePresented(true),
				), testIssuerHTTP01Enabled},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("challenges"),
						"status",
						gen.DefaultTestNamespace,
						gen.ChallengeFrom(baseChallenge,
							gen.SetChallengeProcessing(false),
							gen.SetChallengeURL("testurl"),
							gen.SetChallengeState(cmacme.Invalid),
							gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
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

func TestSyncHappyPathFinalizerLegacyToLegacy(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.UseDomainQualifiedFinalizer, false)
	testSyncHappyPathWithFinalizer(t, cmacme.ACMELegacyFinalizer, cmacme.ACMELegacyFinalizer)
}

func TestSyncHappyPathFinalizerDomainQualifiedToLegacy(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.UseDomainQualifiedFinalizer, false)
	testSyncHappyPathWithFinalizer(t, cmacme.ACMEDomainQualifiedFinalizer, cmacme.ACMELegacyFinalizer)
}

func TestSyncHappyPathFinalizerLegacyToDomainQualified(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.UseDomainQualifiedFinalizer, true)
	testSyncHappyPathWithFinalizer(t, cmacme.ACMELegacyFinalizer, cmacme.ACMEDomainQualifiedFinalizer)
}

func TestSyncHappyPathFinalizerDomainQualifiedToDomainQualified(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.UseDomainQualifiedFinalizer, true)
	testSyncHappyPathWithFinalizer(t, cmacme.ACMEDomainQualifiedFinalizer, cmacme.ACMEDomainQualifiedFinalizer)
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Init()
	defer test.builder.Stop()

	c := &controller{}
	if _, _, err := c.Register(test.builder.Context); err != nil {
		t.Fatal(err)
	}
	c.helper = issuer.NewHelper(
		test.builder.SharedInformerFactory.Certmanager().V1().Issuers().Lister(),
		test.builder.SharedInformerFactory.Certmanager().V1().ClusterIssuers().Lister(),
	)
	c.accountRegistry = &accountstest.FakeRegistry{
		GetClientFunc: func(_ string) (acmecl.Interface, error) {
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
