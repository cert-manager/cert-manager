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

package acmeorders

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"

	acmeapi "golang.org/x/crypto/acme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	accountstest "github.com/jetstack/cert-manager/pkg/acme/accounts/test"
	acmecl "github.com/jetstack/cert-manager/pkg/acme/client"
	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func TestSyncHappyPath(t *testing.T) {
	nowTime := time.Now()
	nowMetaTime := metav1.NewTime(nowTime)
	fixedClock := fakeclock.NewFakeClock(nowTime)

	testIssuerHTTP01 := gen.Issuer("testissuer", gen.SetIssuerACME(cmacme.ACMEIssuer{
		Solvers: []cmacme.ACMEChallengeSolver{
			{
				HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
					Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
				},
			},
		},
	}))

	testIssuerHTTP01TestCom := gen.Issuer("testissuer", gen.SetIssuerACME(cmacme.ACMEIssuer{
		Solvers: []cmacme.ACMEChallengeSolver{
			{
				Selector: &cmacme.CertificateDNSNameSelector{
					DNSNames: []string{"test.com"},
				},
				HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
					Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
				},
			},
		},
	}))

	testIssuerHTTP01TestComPreferredChain := gen.Issuer("testissuer", gen.SetIssuerACME(cmacme.ACMEIssuer{
		PreferredChain: "ISRG Root X1",
		Solvers: []cmacme.ACMEChallengeSolver{
			{
				Selector: &cmacme.CertificateDNSNameSelector{
					DNSNames: []string{"test.com"},
				},
				HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
					Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
				},
			},
		},
	}))

	testOrder := gen.Order("testorder",
		gen.SetOrderCommonName("test.com"),
		gen.SetOrderIssuer(cmmeta.ObjectReference{
			Name: testIssuerHTTP01TestCom.Name,
		}),
	)

	testOrderIP := gen.Order("testorder", gen.SetOrderIssuer(cmmeta.ObjectReference{Name: testIssuerHTTP01.Name}), gen.SetOrderIPAddresses("10.0.0.1"))

	pendingStatus := cmacme.OrderStatus{
		State:       cmacme.Pending,
		URL:         "http://testurl.com/abcde",
		FinalizeURL: "http://testurl.com/abcde/finalize",
		Authorizations: []cmacme.ACMEAuthorization{
			{
				URL:        "http://authzurl",
				Identifier: "test.com",
				Challenges: []cmacme.ACMEChallenge{
					{
						URL:   "http://chalurl",
						Token: "token",
						Type:  "http-01",
					},
				},
			},
		},
	}

	testOrderPending := gen.OrderFrom(testOrder, gen.SetOrderStatus(pendingStatus))
	testOrderInvalid := testOrderPending.DeepCopy()
	testOrderInvalid.Status.State = cmacme.Invalid
	testOrderInvalid.Status.FailureTime = &nowMetaTime
	testOrderValid := testOrderPending.DeepCopy()
	testOrderValid.Status.State = cmacme.Valid
	// pem encoded word 'test'
	testOrderValid.Status.Certificate = []byte(`-----BEGIN CERTIFICATE-----
dGVzdA==
-----END CERTIFICATE-----
`)
	testOrderReady := testOrderPending.DeepCopy()
	testOrderReady.Status.State = cmacme.Ready

	testCert := []byte(`-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIRANOxciY0IzLc9AUoUSrsnGowDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTYxMDA2MTU0MzU1
WhcNMjExMDA2MTU0MzU1WjBKMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDEjMCEGA1UEAxMaTGV0J3MgRW5jcnlwdCBBdXRob3JpdHkgWDMwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCc0wzwWuUuR7dyXTeDs2hjMOrX
NSYZJeG9vjXxcJIvt7hLQQWrqZ41CFjssSrEaIcLo+N15Obzp2JxunmBYB/XkZqf
89B4Z3HIaQ6Vkc/+5pnpYDxIzH7KTXcSJJ1HG1rrueweNwAcnKx7pwXqzkrrvUHl
Npi5y/1tPJZo3yMqQpAMhnRnyH+lmrhSYRQTP2XpgofL2/oOVvaGifOFP5eGr7Dc
Gu9rDZUWfcQroGWymQQ2dYBrrErzG5BJeC+ilk8qICUpBMZ0wNAxzY8xOJUWuqgz
uEPxsR/DMH+ieTETPS02+OP88jNquTkxxa/EjQ0dZBYzqvqEKbbUC8DYfcOTAgMB
AAGjggFnMIIBYzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADBU
BgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEBATAwMC4GCCsGAQUFBwIB
FiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3JnMB0GA1UdDgQWBBSo
SmpjBH3duubRObemRWXv86jsoTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3Js
LnJvb3QteDEubGV0c2VuY3J5cHQub3JnMHIGCCsGAQUFBwEBBGYwZDAwBggrBgEF
BQcwAYYkaHR0cDovL29jc3Aucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcvMDAGCCsG
AQUFBzAChiRodHRwOi8vY2VydC5yb290LXgxLmxldHNlbmNyeXB0Lm9yZy8wHwYD
VR0jBBgwFoAUebRZ5nu25eQBc4AIiMgaWPbpm24wDQYJKoZIhvcNAQELBQADggIB
ABnPdSA0LTqmRf/Q1eaM2jLonG4bQdEnqOJQ8nCqxOeTRrToEKtwT++36gTSlBGx
A/5dut82jJQ2jxN8RI8L9QFXrWi4xXnA2EqA10yjHiR6H9cj6MFiOnb5In1eWsRM
UM2v3e9tNsCAgBukPHAg1lQh07rvFKm/Bz9BCjaxorALINUfZ9DD64j2igLIxle2
DPxW8dI/F2loHMjXZjqG8RkqZUdoxtID5+90FgsGIfkMpqgRS05f4zPbCEHqCXl1
eO5HyELTgcVlLXXQDgAWnRzut1hFJeczY1tjQQno6f6s+nMydLN26WuU4s3UYvOu
OsUxRlJu7TSRHqDC3lSE5XggVkzdaPkuKGQbGpny+01/47hfXXNB7HntWNZ6N2Vw
p7G6OfY+YQrZwIaQmhrIqJZuigsrbe3W+gdn5ykE9+Ky0VgVUsfxo52mwFYs1JKY
2PGDuWx8M6DlS6qQkvHaRUo0FMd8TsSlbF0/v965qGFKhSDeQoMpYnwcmQilRh/0
ayLThlHLN81gSkJjVrPI0Y8xCVPB4twb1PFUd2fPM3sA1tJ83sZ5v8vgFv2yofKR
PB0t6JzUA81mSqM3kxl5e+IZwhYAyO0OTg3/fs8HqGTNKd9BqoUwSRBzp06JMg5b
rUCGwbCUDI0mxadJ3Bz4WxR6fyNpBK2yAinWEsikxqEt
-----END CERTIFICATE-----
`)
	rawTestCert, _ := pem.Decode(testCert)

	testOrderValidAltCert := gen.OrderFrom(testOrder, gen.SetOrderStatus(pendingStatus))
	testOrderValidAltCert.Status.State = cmacme.Valid
	testOrderValidAltCert.Status.Certificate = testCert

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
	testAuthorizationChallengeValid.Status.State = cmacme.Valid
	testAuthorizationChallengeInvalid := testAuthorizationChallenge.DeepCopy()
	testAuthorizationChallengeInvalid.Status.State = cmacme.Invalid

	testACMEAuthorizationPending := &acmeapi.Authorization{
		URI:    "http://authzurl",
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
		URI: testOrderPending.Status.URL,
		Identifiers: []acmeapi.AuthzID{
			{
				Type:  "dns",
				Value: "test.com",
			},
		},
		FinalizeURL: testOrderPending.Status.FinalizeURL,
		AuthzURLs:   []string{"http://authzurl"},
		Status:      acmeapi.StatusPending,
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
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrderPending.Namespace,
						gen.OrderFrom(testOrder, gen.SetOrderStatus(cmacme.OrderStatus{
							State:       cmacme.Pending,
							URL:         "http://testurl.com/abcde",
							FinalizeURL: "http://testurl.com/abcde/finalize",
							Authorizations: []cmacme.ACMEAuthorization{
								{
									URL: "http://authzurl",
								},
							},
						})))),
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeAuthorizeOrder: func(ctx context.Context, id []acmeapi.AuthzID, opt ...acmeapi.OrderOption) (*acmeapi.Order, error) {
					return testACMEOrderPending, nil
				},
				FakeGetAuthorization: func(ctx context.Context, url string) (*acmeapi.Authorization, error) {
					if url != "http://authzurl" {
						return nil, fmt.Errorf("Invalid URL: expected http://authzurl got %q", url)
					}
					return testACMEAuthorizationPending, nil
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"create a new order with the acme server with an IP address": {
			order: testOrderIP,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01, testOrderIP},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrderPending.Namespace,
						gen.OrderFrom(testOrderIP, gen.SetOrderStatus(cmacme.OrderStatus{
							State:       cmacme.Pending,
							URL:         "http://testurl.com/abcde",
							FinalizeURL: "http://testurl.com/abcde/finalize",
							Authorizations: []cmacme.ACMEAuthorization{
								{
									URL: "http://authzurl",
								},
							},
						})))),
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeAuthorizeOrder: func(ctx context.Context, id []acmeapi.AuthzID, opt ...acmeapi.OrderOption) (*acmeapi.Order, error) {
					if id[0].Value != "10.0.0.1" || id[0].Type != "ip" {
						return nil, errors.New("AuthzID needs to be the IP")
					}
					return testACMEOrderPending, nil
				},
				FakeGetAuthorization: func(ctx context.Context, url string) (*acmeapi.Authorization, error) {
					if url != "http://authzurl" {
						return nil, fmt.Errorf("Invalid URL: expected http://authzurl got %q", url)
					}
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
					testpkg.NewAction(coretesting.NewCreateAction(cmacme.SchemeGroupVersion.WithResource("challenges"), testAuthorizationChallenge.Namespace, testAuthorizationChallenge)),
				},
				ExpectedEvents: []string{
					`Normal Created Created Challenge resource "testorder-2179654896" for domain "test.com"`,
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"should refuse to create a challenge if only an unknown challenge type is offered": {
			order: gen.OrderFrom(testOrderPending, gen.SetOrderStatus(cmacme.OrderStatus{
				State:       cmacme.Pending,
				URL:         "http://testurl.com/abcde",
				FinalizeURL: "http://testurl.com/abcde/finalize",
				Authorizations: []cmacme.ACMEAuthorization{
					{
						URL:        "http://authzurl",
						Identifier: "test.com",
						Challenges: []cmacme.ACMEChallenge{
							{
								URL:   "http://chalurl",
								Token: "token",
								Type:  "unknown-type",
							},
						},
					},
				},
			})),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					testIssuerHTTP01TestCom,
				},
				ExpectedEvents: []string{
					// the 'unsupported challenge type' text is not printed here as the code that 'selects'
					// a solver to use for a challenge filters out unsupported challenge types earlier
					// in its selection routine.
					`Warning Solver Failed to determine a valid solver configuration for the set of domains on the Order: no configured challenge solvers can be used for this challenge`,
				},
			},
		},
		// TODO: we should improve this behaviour as this is the 'stuck order' problem described in:
		//  https://github.com/jetstack/cert-manager/issues/2868
		"skip creating a Challenge for an already valid authorization, and do nothing if the order is pending": {
			order: gen.OrderFrom(testOrder, gen.SetOrderStatus(
				cmacme.OrderStatus{
					State:       cmacme.Pending,
					URL:         "http://testurl.com/abcde",
					FinalizeURL: "http://testurl.com/abcde/finalize",
					Authorizations: []cmacme.ACMEAuthorization{
						{
							URL:          "http://authzurl",
							Identifier:   "test.com",
							InitialState: cmacme.Valid,
							Challenges: []cmacme.ACMEChallenge{
								{
									URL:   "http://chalurl",
									Token: "token",
									Type:  "http-01",
								},
							},
						},
					},
				},
			)),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderPending},
				ExpectedActions:    []testpkg.Action{},
				ExpectedEvents:     []string{},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(ctx context.Context, url string) (*acmeapi.Order, error) {
					return &acmeapi.Order{
						URI:         "http://testurl.com/abcde",
						Status:      acmeapi.StatusPending,
						FinalizeURL: "http://testurl.com/abcde/finalize",
						CertURL:     "",
					}, nil
				},
			},
		},
		"skip creating a Challenge for an already valid authorization": {
			order: gen.OrderFrom(testOrder, gen.SetOrderStatus(
				cmacme.OrderStatus{
					State:       cmacme.Pending,
					URL:         "http://testurl.com/abcde",
					FinalizeURL: "http://testurl.com/abcde/finalize",
					Authorizations: []cmacme.ACMEAuthorization{
						{
							URL:          "http://authzurl",
							Identifier:   "test.com",
							InitialState: cmacme.Valid,
							Challenges: []cmacme.ACMEChallenge{
								{
									URL:   "http://chalurl",
									Token: "token",
									Type:  "http-01",
								},
							},
						},
					},
				},
			)),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderPending},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrder.Namespace, gen.OrderFrom(testOrder, gen.SetOrderStatus(
							cmacme.OrderStatus{
								// The 'state' field should be updated to reflect the
								// Order returned by FakeGetOrder
								State:       cmacme.Valid,
								URL:         "http://testurl.com/abcde",
								FinalizeURL: "http://testurl.com/abcde/finalize",
								Authorizations: []cmacme.ACMEAuthorization{
									{
										URL:          "http://authzurl",
										Identifier:   "test.com",
										InitialState: cmacme.Valid,
										Challenges: []cmacme.ACMEChallenge{
											{
												URL:   "http://chalurl",
												Token: "token",
												Type:  "http-01",
											},
										},
									},
								},
							},
						)),
					)),
				},
				ExpectedEvents: []string{},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(ctx context.Context, url string) (*acmeapi.Order, error) {
					return &acmeapi.Order{
						URI:         "http://testurl.com/abcde",
						Status:      acmeapi.StatusValid,
						FinalizeURL: "http://testurl.com/abcde/finalize",
						CertURL:     "",
					}, nil
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
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrderReady.Namespace, testOrderReady)),
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
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrderValid.Namespace, testOrderValid)),
				},
				ExpectedEvents: []string{
					"Normal Complete Order completed successfully",
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderValid, nil
				},
				FakeCreateOrderCert: func(_ context.Context, url string, csr []byte, bundle bool) ([][]byte, string, error) {
					testData := []byte("test")
					return [][]byte{testData}, "http://testurl", nil
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"call FinalizeOrder fetch alternate cert chain": {
			order: testOrderReady.DeepCopy(),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestComPreferredChain, testOrderReady, testAuthorizationChallengeValid},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrderValid.Namespace, testOrderValidAltCert)),
				},
				ExpectedEvents: []string{
					"Normal Complete Order completed successfully",
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderValid, nil
				},
				FakeCreateOrderCert: func(_ context.Context, url string, csr []byte, bundle bool) ([][]byte, string, error) {
					testData := []byte("test")
					return [][]byte{testData}, "http://testurl", nil
				},
				FakeFetchCertAlternatives: func(_ context.Context, url string, bundle bool) ([][][]byte, error) {
					if url != "http://testurl" {
						return nil, errors.New("Cert URL is incorrect")
					}

					return [][][]byte{{rawTestCert.Bytes}}, nil
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
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrderInvalid.Namespace, testOrderInvalid)),
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
	order      *cmacme.Order
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
	c.accountRegistry = &accountstest.FakeRegistry{
		GetClientFunc: func(_ string) (acmecl.Interface, error) {
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
