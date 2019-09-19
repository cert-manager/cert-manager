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
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	acmecl "github.com/jetstack/cert-manager/pkg/acme/client"
	acmefake "github.com/jetstack/cert-manager/pkg/acme/fake"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/test/unit/gen"
	acmeapi "github.com/jetstack/cert-manager/third_party/crypto/acme"
)

func TestSyncHappyPath(t *testing.T) {
	nowTime := time.Now()
	nowMetaTime := metav1.NewTime(nowTime)
	fixedClock := fakeclock.NewFakeClock(nowTime)

	testIssuerHTTP01TestCom := gen.Issuer("testissuer", gen.SetIssuerACME(v1alpha1.ACMEIssuer{
		Solvers: []v1alpha1.ACMEChallengeSolver{
			{
				Selector: &v1alpha1.CertificateDNSNameSelector{
					DNSNames: []string{"test.com"},
				},
				HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
					Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{},
				},
			},
		},
	}))
	testOrder := gen.Order("testorder",
		gen.SetOrderCommonName("test.com"),
		gen.SetOrderIssuer(v1alpha1.ObjectReference{
			Name: testIssuerHTTP01TestCom.Name,
		}),
	)

	pendingStatus := v1alpha1.OrderStatus{
		State:       v1alpha1.Pending,
		URL:         "http://testurl.com/abcde",
		FinalizeURL: "http://testurl.com/abcde/finalize",
		Authorizations: []v1alpha1.ACMEAuthorization{
			{
				URL:        "http://authzurl",
				Identifier: "test.com",
				Challenges: []v1alpha1.ACMEChallenge{
					{
						URL:   "http://chalurl",
						Token: "token",
						Type:  v1alpha1.ACMEChallengeTypeHTTP01,
					},
				},
			},
		},
	}

	testOrderPending := gen.OrderFrom(testOrder, gen.SetOrderStatus(pendingStatus))
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

	fakeHTTP01ACMECl := &acmecl.FakeACME{
		FakeHTTP01ChallengeResponse: func(s string) (string, error) {
			// TODO: assert s = "token"
			return "key", nil
		},
	}
	testAuthorizationChallenge, err := buildChallenge(context.TODO(), fakeHTTP01ACMECl, testIssuerHTTP01TestCom, testOrderPending, testOrderPending.Status.Authorizations[0])
	if err != nil {
		t.Fatalf("error building Challenge resource test fixture: %v", err)
	}
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

	tests := map[string]testT{
		"create a new order with the acme server, set the order url on the status resource and return nil to avoid cache timing issues": {
			order: testOrder,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrder},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrderPending.Namespace,
						gen.OrderFrom(testOrder, gen.SetOrderStatus(v1alpha1.OrderStatus{
							State:       v1alpha1.Pending,
							URL:         "http://testurl.com/abcde",
							FinalizeURL: "http://testurl.com/abcde/finalize",
							Authorizations: []v1alpha1.ACMEAuthorization{
								{
									URL: "http://authzurl",
								},
							},
						})))),
				},
			},
			acmeClient: &acmecl.FakeACME{
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
		},
		"create a challenge resource for the test.com dnsName on the order": {
			order: testOrderPending,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderPending},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(v1alpha1.SchemeGroupVersion.WithResource("challenges"), testAuthorizationChallenge.Namespace, testAuthorizationChallenge)),
				},
				ExpectedEvents: []string{
					`Normal Created Created Challenge resource "testorder-1335133199" for domain "test.com"`,
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"do nothing if the challenge for test.com is still pending": {
			order: testOrderPending,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderPending, testAuthorizationChallenge},
				ExpectedActions:    []testpkg.Action{},
			},
			acmeClient: &acmecl.FakeACME{
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"call GetOrder and update the order state to 'ready' if all challenges are 'valid'": {
			order: testOrderPending,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderPending, testAuthorizationChallengeValid},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrderReady.Namespace, testOrderReady)),
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderReady, nil
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"call FinalizeOrder and update the order state to 'valid' if finalize succeeds": {
			order: testOrderReady,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderReady, testAuthorizationChallengeValid},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrderValid.Namespace, testOrderValid)),
				},
				ExpectedEvents: []string{
					"Normal Complete Order completed successfully",
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderValid, nil
				},
				FakeFinalizeOrder: func(_ context.Context, url string, csr []byte) ([][]byte, error) {
					testData := []byte("test")
					return [][]byte{testData}, nil
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"call GetOrder and update the order state if the challenge is 'failed'": {
			order: testOrderPending,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderPending, testAuthorizationChallengeInvalid},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateAction(v1alpha1.SchemeGroupVersion.WithResource("orders"), testOrderInvalid.Namespace, testOrderInvalid)),
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderInvalid, nil
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					return "key", nil
				},
			},
		},
		"should leave the order state as-is if the challenge is marked invalid but the acme order is pending": {
			order: testOrderPending,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderPending, testAuthorizationChallengeInvalid},
				ExpectedActions:    []testpkg.Action{},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderPending, nil
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"do nothing if the order is valid": {
			order: testOrderValid,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderValid},
				ExpectedActions:    []testpkg.Action{},
			},
			acmeClient: &acmecl.FakeACME{},
		},
		"do nothing if the order is failed": {
			order: testOrderInvalid,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderInvalid},
				ExpectedActions:    []testpkg.Action{},
			},
			acmeClient: &acmecl.FakeACME{},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// reset the fixedClock at the start of each test
			fixedClock.SetTime(nowTime)
			// always use the fixedClock unless otherwise specified
			if test.builder.Clock == nil {
				test.builder.Clock = fixedClock
			}
			runTest(t, test)
		})
	}
}

type testT struct {
	order      *v1alpha1.Order
	builder    *testpkg.Builder
	acmeClient acmecl.Interface
	expectErr  bool
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Init()
	defer test.builder.Stop()

	c := &controller{}
	c.Register(test.builder.Context)
	c.acmeHelper = &acmefake.Helper{
		ClientForIssuerFunc: func(iss v1alpha1.GenericIssuer) (acmecl.Interface, error) {
			return test.acmeClient, nil
		},
	}
	test.builder.Start()

	err := c.Sync(context.Background(), test.order)
	if err != nil && !test.expectErr {
		t.Errorf("Expected function to not error, but got: %v", err)
	}
	if err == nil && test.expectErr {
		t.Errorf("Expected function to get an error, but got: %v", err)
	}

	test.builder.CheckAndFinish(err)
}
