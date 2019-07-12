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

package acmeorders

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/kr/pretty"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/diff"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	acmecl "github.com/jetstack/cert-manager/pkg/acme/client"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	acmeapi "github.com/jetstack/cert-manager/third_party/crypto/acme"
)

func TestSyncHappyPath(t *testing.T) {
	nowTime := time.Now()
	nowMetaTime := metav1.NewTime(nowTime)
	fixedClock := fakeclock.NewFakeClock(nowTime)

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
	testOrder := &v1alpha1.Order{
		ObjectMeta: metav1.ObjectMeta{Name: "testorder", Namespace: "default"},
		Spec: v1alpha1.OrderSpec{
			CommonName: "test.com",
			Config: []v1alpha1.DomainSolverConfig{
				{
					Domains:      []string{"test.com"},
					SolverConfig: v1alpha1.SolverConfig{HTTP01: &v1alpha1.HTTP01SolverConfig{}},
				},
			},
		},
	}

	testOrderPending := testOrder.DeepCopy()
	testOrderPending.Status = v1alpha1.OrderStatus{
		State:       v1alpha1.Pending,
		URL:         "http://testurl.com/abcde",
		FinalizeURL: "http://testurl.com/abcde/finalize",
		Challenges: []v1alpha1.ChallengeSpec{
			{
				AuthzURL: "http://authzurl",
				Type:     "http-01",
				Token:    "token",
				DNSName:  "test.com",
				Key:      "key",
				Config: &v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{
						Ingress: "",
					},
				},
			},
		},
	}
	testOrderInvalid := testOrderPending.DeepCopy()
	testOrderInvalid.Status.State = v1alpha1.Invalid
	testOrderInvalid.Status.FailureTime = &nowMetaTime
	testOrderValid := testOrderPending.DeepCopy()
	testOrderValid.Status.State = v1alpha1.Valid
	// pem encoded word 'test'
	testOrderValid.Status.Certificate = []byte(`-----BEGIN CERTIFICATE-----
dGVzdA==
-----END CERTIFICATE-----
`)
	testOrderReady := testOrderPending.DeepCopy()
	testOrderReady.Status.State = v1alpha1.Ready

	testAuthorizationChallenge := buildChallenge(0, testOrderPending, testOrderPending.Status.Challenges[0])
	testAuthorizationChallengeValid := testAuthorizationChallenge.DeepCopy()
	testAuthorizationChallengeValid.Status.State = v1alpha1.Valid
	testAuthorizationChallengeInvalid := testAuthorizationChallenge.DeepCopy()
	testAuthorizationChallengeInvalid.Status.State = v1alpha1.Invalid

	testACMEAuthorizationPending := &acmeapi.Authorization{
		URL:    "http://authzurl",
		Status: acmeapi.StatusPending,
		Identifier: acmeapi.AuthzID{
			Value: "test.com",
		},
		Challenges: []*acmeapi.Challenge{
			{
				Type:  "http-01",
				Token: "token",
			},
		},
	}

	testACMEOrderPending := &acmeapi.Order{
		URL: testOrderPending.Status.URL,
		Identifiers: []acmeapi.AuthzID{
			{
				Type:  "dns",
				Value: "test.com",
			},
		},
		FinalizeURL:    testOrderPending.Status.FinalizeURL,
		Authorizations: []string{"http://authzurl"},
		Status:         acmeapi.StatusPending,
	}
	// shallow copy
	testACMEOrderValid := &acmeapi.Order{}
	*testACMEOrderValid = *testACMEOrderPending
	testACMEOrderValid.Status = acmeapi.StatusValid
	// shallow copy
	testACMEOrderReady := &acmeapi.Order{}
	*testACMEOrderReady = *testACMEOrderPending
	testACMEOrderReady.Status = acmeapi.StatusReady
	// shallow copy
	testACMEOrderInvalid := &acmeapi.Order{}
	*testACMEOrderInvalid = *testACMEOrderPending
	testACMEOrderInvalid.Status = acmeapi.StatusInvalid

	tests := map[string]controllerFixture{
		"create a new order with the acme server, set the order url on the status resource and return nil to avoid cache timing issues": {
			Issuer: testIssuerHTTP01Enabled,
			Order:  testOrder,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testOrder},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrderPending.Namespace, testOrderPending)),
				},
			},
			Client: &acmecl.FakeACME{
				FakeCreateOrder: func(ctx context.Context, o *acmeapi.Order) (*acmeapi.Order, error) {
					return testACMEOrderPending, nil
				},
				FakeGetAuthorization: func(ctx context.Context, url string) (*acmeapi.Authorization, error) {
					// TODO: assert url = "http://authzurl"
					return testACMEAuthorizationPending, nil
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
		"create a challenge resource for the test.com dnsName on the order": {
			Issuer: testIssuerHTTP01Enabled,
			Order:  testOrderPending,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testOrder},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), testAuthorizationChallenge.Namespace, testAuthorizationChallenge)),
				},
			},
			Client: &acmecl.FakeACME{},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
		"do nothing if the challenge for test.com is still pending": {
			Issuer: testIssuerHTTP01Enabled,
			Order:  testOrderPending,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testOrder, testAuthorizationChallenge},
				ExpectedActions:    []testpkg.Action{},
			},
			Client: &acmecl.FakeACME{},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
		"call GetOrder and update the order state to 'ready' if all challenges are 'valid'": {
			Order: testOrderPending,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testOrderPending, testAuthorizationChallengeValid},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrderReady.Namespace, testOrderReady)),
				},
			},
			Client: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderReady, nil
				},
			},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
		"call FinalizeOrder and update the order state to 'valid' if finalize succeeds": {
			Order: testOrderReady,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testOrderValid, testAuthorizationChallengeValid},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrderValid.Namespace, testOrderValid)),
				},
			},
			Client: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderValid, nil
				},
				FakeFinalizeOrder: func(_ context.Context, url string, csr []byte) ([][]byte, error) {
					testData := []byte("test")
					return [][]byte{testData}, nil
				},
			},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
		"call GetOrder and update the order state if the challenge is 'failed'": {
			Order: testOrderPending,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testOrderPending, testAuthorizationChallengeInvalid},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrderInvalid.Namespace, testOrderInvalid)),
				},
			},
			Client: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderInvalid, nil
				},
			},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
		"should leave the order state as-is if the challenge is marked invalid but the acme order is pending": {
			Order: testOrderPending,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testOrderPending, testAuthorizationChallengeInvalid},
				ExpectedActions:    []testpkg.Action{},
			},
			Client: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderPending, nil
				},
			},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
		"do nothing if the order is valid": {
			Issuer: testIssuerHTTP01Enabled,
			Order:  testOrderValid,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testOrderValid},
				ExpectedActions:    []testpkg.Action{},
			},
			Client: &acmecl.FakeACME{},
			CheckFn: func(t *testing.T, s *controllerFixture, args ...interface{}) {
			},
			Err: false,
		},
		"do nothing if the order is failed": {
			Issuer: testIssuerHTTP01Enabled,
			Order:  testOrderInvalid,
			Builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testOrderInvalid},
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
			if test.Clock == nil {
				test.Clock = fixedClock
			}
			test.Setup(t)
			orderCopy := test.Order.DeepCopy()
			err := test.Controller.Sync(test.Ctx, orderCopy)
			if err != nil && !test.Err {
				t.Errorf("Expected function to not error, but got: %v", err)
			}
			if err == nil && test.Err {
				t.Errorf("Expected function to get an error, but got: %v", err)
			}
			test.Finish(t, orderCopy, err)
		})
	}
}

//func (c *controller) challengeSpecForAuthorization(ctx context.Context, cl acmecl.Interface, issuer cmapi.GenericIssuer, o *cmapi.Order, authz *acmeapi.Authorization) (*cmapi.ChallengeSpec, error) {
func TestChallengeSpecForAuthorization(t *testing.T) {
	// a reusable and very simple ACME client that only implements the HTTP01
	// and DNS01 challenge response/record methods
	basicACMEClient := &acmecl.FakeACME{
		FakeHTTP01ChallengeResponse: func(string) (string, error) {
			return "http01", nil
		},
		FakeDNS01ChallengeRecord: func(string) (string, error) {
			return "dns01", nil
		},
	}
	// define some reusable solvers that are used in multiple unit tests
	emptySelectorSolverHTTP01 := v1alpha1.ACMEChallengeSolver{
		HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
			Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
				Name: "empty-selector-solver",
			},
		},
	}
	emptySelectorSolverDNS01 := v1alpha1.ACMEChallengeSolver{
		DNS01: &v1alpha1.ACMEChallengeSolverDNS01{
			Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
				Email: "test-cloudflare-email",
			},
		},
	}
	nonMatchingSelectorSolver := v1alpha1.ACMEChallengeSolver{
		Selector: &v1alpha1.CertificateDNSNameSelector{
			MatchLabels: map[string]string{
				"label":    "does-not-exist",
				"does-not": "match",
			},
		},
		HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
			Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
				Name: "non-matching-selector-solver",
			},
		},
	}
	exampleComDNSNameSelectorSolver := v1alpha1.ACMEChallengeSolver{
		Selector: &v1alpha1.CertificateDNSNameSelector{
			DNSNames: []string{"example.com"},
		},
		HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
			Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
				Name: "example-com-dns-name-selector-solver",
			},
		},
	}
	// define ACME challenges that are used during tests
	acmeChallengeHTTP01 := &acmeapi.Challenge{
		Type:  "http-01",
		Token: "http-01-token",
	}
	acmeChallengeDNS01 := &acmeapi.Challenge{
		Type:  "dns-01",
		Token: "dns-01-token",
	}

	tests := map[string]struct {
		acmeClient acmecl.Interface
		issuer     v1alpha1.GenericIssuer
		order      *v1alpha1.Order
		authz      *acmeapi.Authorization

		expectedChallengeSpec *v1alpha1.ChallengeSpec
		expectedError         bool
	}{
		"should use configured default solver when no others are present": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{emptySelectorSolverHTTP01},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "http-01",
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  &emptySelectorSolverHTTP01,
			},
		},
		"should use configured default solver when no others are present but selector is non-nil": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{},
									HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
										Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
											Name: "empty-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "http-01",
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver: &v1alpha1.ACMEChallengeSolver{
					Selector: &v1alpha1.CertificateDNSNameSelector{},
					HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
						Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
							Name: "empty-selector-solver",
						},
					},
				},
			},
		},
		"should use configured default solver when others do not match": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								emptySelectorSolverHTTP01,
								nonMatchingSelectorSolver,
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "http-01",
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  &emptySelectorSolverHTTP01,
			},
		},
		"should use DNS01 solver over HTTP01 if challenge is of type DNS01": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								emptySelectorSolverHTTP01,
								emptySelectorSolverDNS01,
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeDNS01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "dns-01",
				DNSName: "example.com",
				Token:   acmeChallengeDNS01.Token,
				Key:     "dns01",
				Solver:  &emptySelectorSolverDNS01,
			},
		},
		"should return an error if none match": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								nonMatchingSelectorSolver,
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedError: true,
		},
		"uses correct solver when selector explicitly names dnsName": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								emptySelectorSolverHTTP01,
								exampleComDNSNameSelectorSolver,
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "http-01",
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  &exampleComDNSNameSelectorSolver,
			},
		},
		"uses default solver if dnsName does not match": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								emptySelectorSolverHTTP01,
								exampleComDNSNameSelectorSolver,
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"notexample.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "notexample.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "http-01",
				DNSName: "notexample.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  &emptySelectorSolverHTTP01,
			},
		},
		"if two solvers specify the same dnsName, the one with the most labels should be chosen": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								exampleComDNSNameSelectorSolver,
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										MatchLabels: map[string]string{
											"label": "exists",
										},
										DNSNames: []string{"example.com"},
									},
									HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
										Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-dns-name-labels-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"label": "exists",
					},
				},
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "http-01",
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver: &v1alpha1.ACMEChallengeSolver{
					Selector: &v1alpha1.CertificateDNSNameSelector{
						MatchLabels: map[string]string{
							"label": "exists",
						},
						DNSNames: []string{"example.com"},
					},
					HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
						Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
							Name: "example-com-dns-name-labels-selector-solver",
						},
					},
				},
			},
		},
		"if one solver matches with dnsNames, and the other solver matches with labels, the dnsName solver should be chosen": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								exampleComDNSNameSelectorSolver,
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										MatchLabels: map[string]string{
											"label": "exists",
										},
									},
									HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
										Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-labels-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"label": "exists",
					},
				},
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "http-01",
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  &exampleComDNSNameSelectorSolver,
			},
		},
		// identical to the test above, but the solvers are listed in reverse
		// order to ensure that this behaviour isn't just incidental
		"if one solver matches with dnsNames, and the other solver matches with labels, the dnsName solver should be chosen (solvers listed in reverse order)": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										MatchLabels: map[string]string{
											"label": "exists",
										},
									},
									HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
										Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-labels-selector-solver",
										},
									},
								},
								exampleComDNSNameSelectorSolver,
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"label": "exists",
					},
				},
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "http-01",
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  &exampleComDNSNameSelectorSolver,
			},
		},
		"if one solver matches with dnsNames, and the other solver matches with 2 labels, the dnsName solver should be chosen": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								exampleComDNSNameSelectorSolver,
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										MatchLabels: map[string]string{
											"label":   "exists",
											"another": "label",
										},
									},
									HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
										Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-labels-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"label":   "exists",
						"another": "label",
					},
				},
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "http-01",
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  &exampleComDNSNameSelectorSolver,
			},
		},
		"should choose the solver with the most labels matching if multiple match": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										MatchLabels: map[string]string{
											"label": "exists",
										},
									},
									HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
										Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-labels-selector-solver",
										},
									},
								},
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										MatchLabels: map[string]string{
											"label":   "exists",
											"another": "matches",
										},
									},
									HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
										Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-multiple-labels-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"label":   "exists",
						"another": "matches",
					},
				},
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "http-01",
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver: &v1alpha1.ACMEChallengeSolver{
					Selector: &v1alpha1.CertificateDNSNameSelector{
						MatchLabels: map[string]string{
							"label":   "exists",
							"another": "matches",
						},
					},
					HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
						Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
							Name: "example-com-multiple-labels-selector-solver",
						},
					},
				},
			},
		},
		"should match wildcard dnsName solver if authorization has Wildcard=true": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								emptySelectorSolverDNS01,
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										DNSNames: []string{"*.example.com"},
									},
									DNS01: &v1alpha1.ACMEChallengeSolverDNS01{
										Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
											Email: "example-com-wc-dnsname-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"*.example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
				Wildcard:   true,
				Challenges: []*acmeapi.Challenge{acmeChallengeDNS01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:     "dns-01",
				DNSName:  "example.com",
				Wildcard: true,
				Token:    acmeChallengeDNS01.Token,
				Key:      "dns01",
				Solver: &v1alpha1.ACMEChallengeSolver{
					Selector: &v1alpha1.CertificateDNSNameSelector{
						DNSNames: []string{"*.example.com"},
					},
					DNS01: &v1alpha1.ACMEChallengeSolverDNS01{
						Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
							Email: "example-com-wc-dnsname-selector-solver",
						},
					},
				},
			},
		},
		"dnsName selectors should take precedence over dnsZone selectors": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								exampleComDNSNameSelectorSolver,
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										DNSZones: []string{"com"},
									},
									HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
										Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
											Name: "com-dnszone-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "http-01",
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  &exampleComDNSNameSelectorSolver,
			},
		},
		"dnsName selectors should take precedence over dnsZone selectors (reversed order)": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										DNSZones: []string{"com"},
									},
									DNS01: &v1alpha1.ACMEChallengeSolverDNS01{
										Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
											Email: "com-dnszone-selector-solver",
										},
									},
								},
								exampleComDNSNameSelectorSolver,
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "http-01",
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  &exampleComDNSNameSelectorSolver,
			},
		},
		"should allow matching with dnsZones": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								emptySelectorSolverDNS01,
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										DNSZones: []string{"example.com"},
									},
									DNS01: &v1alpha1.ACMEChallengeSolverDNS01{
										Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
											Email: "example-com-dnszone-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"www.example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "www.example.com",
				},
				Wildcard:   true,
				Challenges: []*acmeapi.Challenge{acmeChallengeDNS01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:     "dns-01",
				DNSName:  "www.example.com",
				Wildcard: true,
				Token:    acmeChallengeDNS01.Token,
				Key:      "dns01",
				Solver: &v1alpha1.ACMEChallengeSolver{
					Selector: &v1alpha1.CertificateDNSNameSelector{
						DNSZones: []string{"example.com"},
					},
					DNS01: &v1alpha1.ACMEChallengeSolverDNS01{
						Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
							Email: "example-com-dnszone-selector-solver",
						},
					},
				},
			},
		},
		"most specific dnsZone should be selected if multiple match": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										DNSZones: []string{"example.com"},
									},
									DNS01: &v1alpha1.ACMEChallengeSolverDNS01{
										Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
											Email: "example-com-dnszone-selector-solver",
										},
									},
								},
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										DNSZones: []string{"prod.example.com"},
									},
									DNS01: &v1alpha1.ACMEChallengeSolverDNS01{
										Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
											Email: "prod-example-com-dnszone-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"www.prod.example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "www.prod.example.com",
				},
				Wildcard:   true,
				Challenges: []*acmeapi.Challenge{acmeChallengeDNS01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:     "dns-01",
				DNSName:  "www.prod.example.com",
				Wildcard: true,
				Token:    acmeChallengeDNS01.Token,
				Key:      "dns01",
				Solver: &v1alpha1.ACMEChallengeSolver{
					Selector: &v1alpha1.CertificateDNSNameSelector{
						DNSZones: []string{"prod.example.com"},
					},
					DNS01: &v1alpha1.ACMEChallengeSolverDNS01{
						Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
							Email: "prod-example-com-dnszone-selector-solver",
						},
					},
				},
			},
		},
		"most specific dnsZone should be selected if multiple match (reversed)": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										DNSZones: []string{"prod.example.com"},
									},
									DNS01: &v1alpha1.ACMEChallengeSolverDNS01{
										Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
											Email: "prod-example-com-dnszone-selector-solver",
										},
									},
								},
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										DNSZones: []string{"example.com"},
									},
									DNS01: &v1alpha1.ACMEChallengeSolverDNS01{
										Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
											Email: "example-com-dnszone-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"www.prod.example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "www.prod.example.com",
				},
				Wildcard:   true,
				Challenges: []*acmeapi.Challenge{acmeChallengeDNS01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:     "dns-01",
				DNSName:  "www.prod.example.com",
				Wildcard: true,
				Token:    acmeChallengeDNS01.Token,
				Key:      "dns01",
				Solver: &v1alpha1.ACMEChallengeSolver{
					Selector: &v1alpha1.CertificateDNSNameSelector{
						DNSZones: []string{"prod.example.com"},
					},
					DNS01: &v1alpha1.ACMEChallengeSolverDNS01{
						Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
							Email: "prod-example-com-dnszone-selector-solver",
						},
					},
				},
			},
		},
		"if two solvers specify the same dnsZone, the one with the most labels should be chosen": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										DNSZones: []string{"example.com"},
									},
									HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
										Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-dnszone-selector-solver",
										},
									},
								},
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										MatchLabels: map[string]string{
											"label": "exists",
										},
										DNSZones: []string{"example.com"},
									},
									HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
										Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-dnszone-labels-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"label": "exists",
					},
				},
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"www.example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "www.example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "http-01",
				DNSName: "www.example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver: &v1alpha1.ACMEChallengeSolver{
					Selector: &v1alpha1.CertificateDNSNameSelector{
						MatchLabels: map[string]string{
							"label": "exists",
						},
						DNSZones: []string{"example.com"},
					},
					HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
						Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
							Name: "example-com-dnszone-labels-selector-solver",
						},
					},
				},
			},
		},
		"if both solvers match dnsNames, and one also matches dnsZones, choose the one that matches dnsZones": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										DNSNames: []string{"www.example.com"},
									},
									HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
										Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-dnsname-selector-solver",
										},
									},
								},
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										DNSZones: []string{"example.com"},
										DNSNames: []string{"www.example.com"},
									},
									HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
										Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-dnsname-dnszone-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"www.example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "www.example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "http-01",
				DNSName: "www.example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver: &v1alpha1.ACMEChallengeSolver{
					Selector: &v1alpha1.CertificateDNSNameSelector{
						DNSZones: []string{"example.com"},
						DNSNames: []string{"www.example.com"},
					},
					HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
						Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
							Name: "example-com-dnsname-dnszone-selector-solver",
						},
					},
				},
			},
		},
		"if both solvers match dnsNames, and one also matches dnsZones, choose the one that matches dnsZones (reversed)": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										DNSZones: []string{"example.com"},
										DNSNames: []string{"www.example.com"},
									},
									HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
										Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-dnsname-dnszone-selector-solver",
										},
									},
								},
								{
									Selector: &v1alpha1.CertificateDNSNameSelector{
										DNSNames: []string{"www.example.com"},
									},
									HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
										Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-dnsname-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"www.example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "www.example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "http-01",
				DNSName: "www.example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver: &v1alpha1.ACMEChallengeSolver{
					Selector: &v1alpha1.CertificateDNSNameSelector{
						DNSZones: []string{"example.com"},
						DNSNames: []string{"www.example.com"},
					},
					HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
						Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
							Name: "example-com-dnsname-dnszone-selector-solver",
						},
					},
				},
			},
		},
		"uses correct solver when selector explicitly names dnsName (reversed)": {
			acmeClient: basicACMEClient,
			issuer: &v1alpha1.Issuer{
				Spec: v1alpha1.IssuerSpec{
					IssuerConfig: v1alpha1.IssuerConfig{
						ACME: &v1alpha1.ACMEIssuer{
							Solvers: []v1alpha1.ACMEChallengeSolver{
								exampleComDNSNameSelectorSolver,
								emptySelectorSolverHTTP01,
							},
						},
					},
				},
			},
			order: &v1alpha1.Order{
				Spec: v1alpha1.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
				Challenges: []*acmeapi.Challenge{acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &v1alpha1.ChallengeSpec{
				Type:    "http-01",
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  &exampleComDNSNameSelectorSolver,
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cs, err := challengeSpecForAuthorization(ctx, test.acmeClient, test.issuer, test.order, test.authz)
			if err != nil && !test.expectedError {
				t.Errorf("expected to not get an error, but got: %v", err)
				t.Fail()
			}
			if err == nil && test.expectedError {
				t.Errorf("expected to get an error, but got none")
			}
			if !reflect.DeepEqual(cs, test.expectedChallengeSpec) {
				t.Errorf("returned challenge spec was not as expected: %v", pretty.Diff(test.expectedChallengeSpec, cs))
			}
		})
	}
}

func TestSolverConfigurationForAuthorization(t *testing.T) {
	type testT struct {
		cfg         []v1alpha1.DomainSolverConfig
		authz       *acmeapi.Authorization
		expectedCfg *v1alpha1.SolverConfig
		expectedErr bool
	}
	tests := map[string]testT{
		"correctly selects normal domain": {
			cfg: []v1alpha1.DomainSolverConfig{
				{
					Domains: []string{"example.com"},
					SolverConfig: v1alpha1.SolverConfig{
						DNS01: &v1alpha1.DNS01SolverConfig{
							Provider: "correctdns",
						},
					},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
			},
			expectedCfg: &v1alpha1.SolverConfig{
				DNS01: &v1alpha1.DNS01SolverConfig{
					Provider: "correctdns",
				},
			},
		},
		"correctly selects normal domain with multiple domains configured": {
			cfg: []v1alpha1.DomainSolverConfig{
				{
					Domains: []string{"notexample.com", "example.com"},
					SolverConfig: v1alpha1.SolverConfig{
						DNS01: &v1alpha1.DNS01SolverConfig{
							Provider: "correctdns",
						},
					},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
			},
			expectedCfg: &v1alpha1.SolverConfig{
				DNS01: &v1alpha1.DNS01SolverConfig{
					Provider: "correctdns",
				},
			},
		},
		"correctly selects normal domain with multiple domains configured separately": {
			cfg: []v1alpha1.DomainSolverConfig{
				{
					Domains: []string{"example.com"},
					SolverConfig: v1alpha1.SolverConfig{
						DNS01: &v1alpha1.DNS01SolverConfig{
							Provider: "correctdns",
						},
					},
				},
				{
					Domains: []string{"notexample.com"},
					SolverConfig: v1alpha1.SolverConfig{
						DNS01: &v1alpha1.DNS01SolverConfig{
							Provider: "incorrectdns",
						},
					},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
			},
			expectedCfg: &v1alpha1.SolverConfig{
				DNS01: &v1alpha1.DNS01SolverConfig{
					Provider: "correctdns",
				},
			},
		},
		"correctly selects configuration for wildcard domain": {
			cfg: []v1alpha1.DomainSolverConfig{
				{
					Domains: []string{"example.com"},
					SolverConfig: v1alpha1.SolverConfig{
						DNS01: &v1alpha1.DNS01SolverConfig{
							Provider: "incorrectdns",
						},
					},
				},
				{
					Domains: []string{"*.example.com"},
					SolverConfig: v1alpha1.SolverConfig{
						DNS01: &v1alpha1.DNS01SolverConfig{
							Provider: "correctdns",
						},
					},
				},
			},
			authz: &acmeapi.Authorization{
				Wildcard: true,
				Identifier: acmeapi.AuthzID{
					// identifiers for wildcards do not include the *. prefix and
					// instead set the Wildcard field on the Authz object
					Value: "example.com",
				},
			},
			expectedCfg: &v1alpha1.SolverConfig{
				DNS01: &v1alpha1.DNS01SolverConfig{
					Provider: "correctdns",
				},
			},
		},
		"returns an error when configuration for the domain is not found": {
			cfg: []v1alpha1.DomainSolverConfig{
				{
					Domains: []string{"notexample.com"},
					SolverConfig: v1alpha1.SolverConfig{
						DNS01: &v1alpha1.DNS01SolverConfig{
							Provider: "incorrectdns",
						},
					},
				},
			},
			authz: &acmeapi.Authorization{
				Identifier: acmeapi.AuthzID{
					Value: "example.com",
				},
			},
			expectedErr: true,
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			actualCfg, err := solverConfigurationForAuthorization(test.cfg, test.authz)
			if err != nil && !test.expectedErr {
				t.Errorf("Expected to return non-nil error, but got %v", err)
				return
			}
			if err == nil && test.expectedErr {
				t.Errorf("Expected error, but got none")
				return
			}
			if !reflect.DeepEqual(test.expectedCfg, actualCfg) {
				t.Errorf("Expected did not equal actual: %v", diff.ObjectDiff(test.expectedCfg, actualCfg))
			}
		})
	}
}
