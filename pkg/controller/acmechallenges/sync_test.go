package acmechallenges

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	acmecl "github.com/jetstack/cert-manager/pkg/acme/client"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	acmeapi "github.com/jetstack/cert-manager/third_party/crypto/acme"
)

// Present the challenge value with the given solver.
func (f *fakeSolver) Present(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	return f.fakePresent(ctx, issuer, ch)
}

// Check should return Error only if propagation check cannot be performed.
// It MUST return `false, nil` if can contact all relevant services and all is
// doing is waiting for propagation
func (f *fakeSolver) Check(ch *v1alpha1.Challenge) (bool, error) {
	return f.fakeCheck(ch)
}

// CleanUp will remove challenge records for a given solver.
// This may involve deleting resources in the Kubernetes API Server, or
// communicating with other external components (e.g. DNS providers).
func (f *fakeSolver) CleanUp(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	return f.fakeCleanUp(ctx, issuer, ch)
}

type fakeSolver struct {
	fakePresent func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error
	fakeCheck   func(ch *v1alpha1.Challenge) (bool, error)
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

	// build actual test fixtures
	testChallenge := &v1alpha1.Challenge{
		ObjectMeta: metav1.ObjectMeta{Name: "testchal", Namespace: "default"},
		Spec: v1alpha1.ChallengeSpec{
			AuthzURL: "http://authzurl",
			URL:      "http://chalurl",
			Type:     "http-01",
			Token:    "token",
			DNSName:  "test.com",
			Key:      "key",
			Config: v1alpha1.SolverConfig{
				HTTP01: &v1alpha1.HTTP01SolverConfig{
					Ingress: "",
				},
			},
		},
	}

	testChallengePending := testChallenge.DeepCopy()
	testChallengePending.Status = v1alpha1.ChallengeStatus{
		State: v1alpha1.Pending,
	}
	testChallengeInvalid := testChallengePending.DeepCopy()
	testChallengeInvalid.Status.State = v1alpha1.Invalid
	testChallengeValid := testChallengePending.DeepCopy()
	testChallengeValid.Status.State = v1alpha1.Valid
	testChallengeReady := testChallengePending.DeepCopy()
	testChallengeReady.Status.State = v1alpha1.Ready

	testChallengePendingPresented := testChallengePending.DeepCopy()
	testChallengePendingPresented.Status.Presented = true
	testChallengePendingPresented.Status.Reason = "Waiting for http-01 challenge propagation"
	testChallengeValidPresented := testChallengeValid.DeepCopy()
	testChallengeValidPresented.Status.Presented = true
	testChallengeValidPresented.Status.Reason = "Successfully authorized domain"
	testChallengeInvalidPresented := testChallengeInvalid.DeepCopy()
	testChallengeInvalidPresented.Status.Presented = true
	testChallengeInvalidPresented.Status.Reason = `Authorization status is "invalid" and not 'valid'`

	testACMEChallengePending := &acmeapi.Challenge{
		URL:    "http://chalurl",
		Status: acmeapi.StatusPending,
		Type:   "http-01",
		Token:  "token",
	}
	// shallow copy
	testACMEChallengeValid := &acmeapi.Challenge{}
	*testACMEChallengeValid = *testACMEChallengePending
	testACMEChallengeValid.Status = acmeapi.StatusValid
	// shallow copy
	testACMEChallengeReady := &acmeapi.Challenge{}
	*testACMEChallengeReady = *testACMEChallengePending
	testACMEChallengeReady.Status = acmeapi.StatusReady
	// shallow copy
	testACMEChallengeInvalid := &acmeapi.Challenge{}
	*testACMEChallengeInvalid = *testACMEChallengePending
	testACMEChallengeInvalid.Status = acmeapi.StatusInvalid

	testACMEAuthorizationPending := &acmeapi.Authorization{
		URL:    "http://authzurl",
		Status: acmeapi.StatusPending,
		Identifier: acmeapi.AuthzID{
			Value: "test.com",
		},
		Challenges: []*acmeapi.Challenge{
			{
				URL:   "http://chalurl",
				Type:  "http-01",
				Token: "token",
			},
		},
	}
	// shallow copy
	testACMEAuthorizationValid := &acmeapi.Authorization{}
	*testACMEAuthorizationValid = *testACMEAuthorizationPending
	testACMEAuthorizationValid.Status = acmeapi.StatusValid
	// shallow copy
	testACMEAuthorizationReady := &acmeapi.Authorization{}
	*testACMEAuthorizationReady = *testACMEAuthorizationPending
	testACMEAuthorizationReady.Status = acmeapi.StatusReady
	// shallow copy
	testACMEAuthorizationInvalid := &acmeapi.Authorization{}
	*testACMEAuthorizationInvalid = *testACMEAuthorizationPending
	testACMEAuthorizationInvalid.Status = acmeapi.StatusInvalid

	tests := map[string]controllerFixture{
		"update status if state is unknown": {
			Issuer:    testIssuerHTTP01Enabled,
			Challenge: testChallenge,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testChallenge},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), testChallengePending.Namespace, testChallengePending)),
				},
			},
			Client: &acmecl.FakeACME{
				FakeGetChallenge: func(ctx context.Context, url string) (*acmeapi.Challenge, error) {
					return testACMEChallengePending, nil
				},
			},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
		"call Present and update challenge status to presented": {
			Issuer:    testIssuerHTTP01Enabled,
			Challenge: testChallengePending,
			HTTP01: &fakeSolver{
				fakePresent: func(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
					return nil
				},
				fakeCheck: func(ch *v1alpha1.Challenge) (bool, error) {
					return false, nil
				},
			},
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testChallengePending},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), testChallengePendingPresented.Namespace, testChallengePendingPresented)),
				},
			},
			Client: &acmecl.FakeACME{},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: true,
		},
		"accept the challenge if the self check is passing": {
			Issuer:    testIssuerHTTP01Enabled,
			Challenge: testChallengePendingPresented,
			HTTP01: &fakeSolver{
				fakeCheck: func(ch *v1alpha1.Challenge) (bool, error) {
					return true, nil
				},
				fakeCleanUp: func(context.Context, v1alpha1.GenericIssuer, *v1alpha1.Challenge) error {
					return nil
				},
			},
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testChallengePendingPresented},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), testChallengeValidPresented.Namespace, testChallengeValidPresented)),
				},
			},
			Client: &acmecl.FakeACME{
				FakeAcceptChallenge: func(context.Context, *acmeapi.Challenge) (*acmeapi.Challenge, error) {
					// return something other than valid here so we can verify that
					// the challenge.status.state is set to the *authorizations*
					// status and not the challenges
					return testACMEChallengePending, nil
				},
				FakeWaitAuthorization: func(context.Context, string) (*acmeapi.Authorization, error) {
					return testACMEAuthorizationValid, nil
				},
			},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
		"mark certificate as failed if accepting the authorization fails": {
			Issuer:    testIssuerHTTP01Enabled,
			Challenge: testChallengePendingPresented,
			HTTP01: &fakeSolver{
				fakeCheck: func(ch *v1alpha1.Challenge) (bool, error) {
					return true, nil
				},
				fakeCleanUp: func(context.Context, v1alpha1.GenericIssuer, *v1alpha1.Challenge) error {
					return nil
				},
			},
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testChallengePendingPresented},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), testChallengeInvalidPresented.Namespace, testChallengeInvalidPresented)),
				},
			},
			Client: &acmecl.FakeACME{
				FakeAcceptChallenge: func(context.Context, *acmeapi.Challenge) (*acmeapi.Challenge, error) {
					// return something other than invalid here so we can verify that
					// the challenge.status.state is set to the *authorizations*
					// status and not the challenges
					return testACMEChallengePending, nil
				},
				FakeWaitAuthorization: func(context.Context, string) (*acmeapi.Authorization, error) {
					return testACMEAuthorizationInvalid, nil
				},
			},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: true,
		},
		"do nothing if the challenge is valid": {
			Issuer:    testIssuerHTTP01Enabled,
			Challenge: testChallengeValid,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testChallengeValid},
				ExpectedActions:    []testpkg.Action{},
			},
			Client: &acmecl.FakeACME{},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
		"do nothing if the challenge is failed": {
			Issuer:    testIssuerHTTP01Enabled,
			Challenge: testChallengeInvalid,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testChallengeInvalid},
				ExpectedActions:    []testpkg.Action{},
			},
			Client: &acmecl.FakeACME{},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.Builder == nil {
				test.Builder = &testpkg.Builder{}
			}
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
