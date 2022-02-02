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
	"reflect"
	"testing"

	"github.com/kr/pretty"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

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
	emptySelectorSolverHTTP01 := cmacme.ACMEChallengeSolver{
		HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
			Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
				Name: "empty-selector-solver",
			},
		},
	}
	emptySelectorSolverDNS01 := cmacme.ACMEChallengeSolver{
		DNS01: &cmacme.ACMEChallengeSolverDNS01{
			Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
				Email: "test-cloudflare-email",
			},
		},
	}
	nonMatchingSelectorSolver := cmacme.ACMEChallengeSolver{
		Selector: &cmacme.CertificateDNSNameSelector{
			MatchLabels: map[string]string{
				"label":    "does-not-exist",
				"does-not": "match",
			},
		},
		HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
			Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
				Name: "non-matching-selector-solver",
			},
		},
	}
	exampleComDNSNameSelectorSolver := cmacme.ACMEChallengeSolver{
		Selector: &cmacme.CertificateDNSNameSelector{
			DNSNames: []string{"example.com"},
		},
		HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
			Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
				Name: "example-com-dns-name-selector-solver",
			},
		},
	}
	// define ACME challenges that are used during tests
	acmeChallengeHTTP01 := &cmacme.ACMEChallenge{
		Type:  "http-01",
		Token: "http-01-token",
	}
	acmeChallengeDNS01 := &cmacme.ACMEChallenge{
		Type:  "dns-01",
		Token: "dns-01-token",
	}

	tests := map[string]struct {
		acmeClient acmecl.Interface
		issuer     v1.GenericIssuer
		order      *cmacme.Order
		authz      *cmacme.ACMEAuthorization

		expectedChallengeSpec *cmacme.ChallengeSpec
		expectedError         bool
	}{
		"should override the ingress name to edit if override annotation is specified": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{emptySelectorSolverHTTP01},
						},
					},
				},
			},
			order: &cmacme.Order{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						cmacme.ACMECertificateHTTP01IngressNameOverride: "test-name-to-override",
					},
				},
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver: cmacme.ACMEChallengeSolver{
					HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
						Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
							Name: "test-name-to-override",
						},
					},
				},
			},
		},
		"should override the ingress class to edit if override annotation is specified": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{emptySelectorSolverHTTP01},
						},
					},
				},
			},
			order: &cmacme.Order{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						cmacme.ACMECertificateHTTP01IngressClassOverride: "test-class-to-override",
					},
				},
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver: cmacme.ACMEChallengeSolver{
					HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
						Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
							Class: pointer.StringPtr("test-class-to-override"),
						},
					},
				},
			},
		},
		"should return an error if both ingress class and name override annotations are set": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{emptySelectorSolverHTTP01},
						},
					},
				},
			},
			order: &cmacme.Order{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						cmacme.ACMECertificateHTTP01IngressNameOverride:  "test-name-to-override",
						cmacme.ACMECertificateHTTP01IngressClassOverride: "test-class-to-override",
					},
				},
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedError: true,
		},
		"should ignore HTTP01 override annotations if DNS01 solver is chosen": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{emptySelectorSolverDNS01},
						},
					},
				},
			},
			order: &cmacme.Order{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						cmacme.ACMECertificateHTTP01IngressNameOverride: "test-name-to-override",
					},
				},
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeDNS01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeDNS01,
				DNSName: "example.com",
				Token:   acmeChallengeDNS01.Token,
				Key:     "dns01",
				Solver:  emptySelectorSolverDNS01,
			},
		},
		"should use configured default solver when no others are present": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{emptySelectorSolverHTTP01},
						},
					},
				},
			},
			order: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  emptySelectorSolverHTTP01,
			},
		},
		"should use configured default solver when no others are present but selector is non-nil": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								{
									Selector: &cmacme.CertificateDNSNameSelector{},
									HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
										Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
											Name: "empty-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver: cmacme.ACMEChallengeSolver{
					Selector: &cmacme.CertificateDNSNameSelector{},
					HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
						Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
							Name: "empty-selector-solver",
						},
					},
				},
			},
		},
		"should use configured default solver when others do not match": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								emptySelectorSolverHTTP01,
								nonMatchingSelectorSolver,
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  emptySelectorSolverHTTP01,
			},
		},
		"should use DNS01 solver over HTTP01 if challenge is of type DNS01": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								emptySelectorSolverHTTP01,
								emptySelectorSolverDNS01,
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeDNS01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeDNS01,
				DNSName: "example.com",
				Token:   acmeChallengeDNS01.Token,
				Key:     "dns01",
				Solver:  emptySelectorSolverDNS01,
			},
		},
		"should return an error if none match": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								nonMatchingSelectorSolver,
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedError: true,
		},
		"uses correct solver when selector explicitly names dnsName": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								emptySelectorSolverHTTP01,
								exampleComDNSNameSelectorSolver,
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  exampleComDNSNameSelectorSolver,
			},
		},
		"uses default solver if dnsName does not match": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								emptySelectorSolverHTTP01,
								exampleComDNSNameSelectorSolver,
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"notexample.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "notexample.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "notexample.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  emptySelectorSolverHTTP01,
			},
		},
		"if two solvers specify the same dnsName, the one with the most labels should be chosen": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								exampleComDNSNameSelectorSolver,
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										MatchLabels: map[string]string{
											"label": "exists",
										},
										DNSNames: []string{"example.com"},
									},
									HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
										Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-dns-name-labels-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"label": "exists",
					},
				},
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver: cmacme.ACMEChallengeSolver{
					Selector: &cmacme.CertificateDNSNameSelector{
						MatchLabels: map[string]string{
							"label": "exists",
						},
						DNSNames: []string{"example.com"},
					},
					HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
						Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
							Name: "example-com-dns-name-labels-selector-solver",
						},
					},
				},
			},
		},
		"if one solver matches with dnsNames, and the other solver matches with labels, the dnsName solver should be chosen": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								exampleComDNSNameSelectorSolver,
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										MatchLabels: map[string]string{
											"label": "exists",
										},
									},
									HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
										Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-labels-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"label": "exists",
					},
				},
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  exampleComDNSNameSelectorSolver,
			},
		},
		// identical to the test above, but the solvers are listed in reverse
		// order to ensure that this behaviour isn't just incidental
		"if one solver matches with dnsNames, and the other solver matches with labels, the dnsName solver should be chosen (solvers listed in reverse order)": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										MatchLabels: map[string]string{
											"label": "exists",
										},
									},
									HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
										Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
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
			order: &cmacme.Order{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"label": "exists",
					},
				},
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  exampleComDNSNameSelectorSolver,
			},
		},
		"if one solver matches with dnsNames, and the other solver matches with 2 labels, the dnsName solver should be chosen": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								exampleComDNSNameSelectorSolver,
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										MatchLabels: map[string]string{
											"label":   "exists",
											"another": "label",
										},
									},
									HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
										Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-labels-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"label":   "exists",
						"another": "label",
					},
				},
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  exampleComDNSNameSelectorSolver,
			},
		},
		"should choose the solver with the most labels matching if multiple match": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										MatchLabels: map[string]string{
											"label": "exists",
										},
									},
									HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
										Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-labels-selector-solver",
										},
									},
								},
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										MatchLabels: map[string]string{
											"label":   "exists",
											"another": "matches",
										},
									},
									HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
										Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-multiple-labels-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"label":   "exists",
						"another": "matches",
					},
				},
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver: cmacme.ACMEChallengeSolver{
					Selector: &cmacme.CertificateDNSNameSelector{
						MatchLabels: map[string]string{
							"label":   "exists",
							"another": "matches",
						},
					},
					HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
						Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
							Name: "example-com-multiple-labels-selector-solver",
						},
					},
				},
			},
		},
		"should match wildcard dnsName solver if authorization has Wildcard=true": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								emptySelectorSolverDNS01,
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										DNSNames: []string{"*.example.com"},
									},
									DNS01: &cmacme.ACMEChallengeSolverDNS01{
										Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
											Email: "example-com-wc-dnsname-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"*.example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Wildcard:   pointer.BoolPtr(true),
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeDNS01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:     cmacme.ACMEChallengeTypeDNS01,
				DNSName:  "example.com",
				Wildcard: true,
				Token:    acmeChallengeDNS01.Token,
				Key:      "dns01",
				Solver: cmacme.ACMEChallengeSolver{
					Selector: &cmacme.CertificateDNSNameSelector{
						DNSNames: []string{"*.example.com"},
					},
					DNS01: &cmacme.ACMEChallengeSolverDNS01{
						Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
							Email: "example-com-wc-dnsname-selector-solver",
						},
					},
				},
			},
		},
		"dnsName selectors should take precedence over dnsZone selectors": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								exampleComDNSNameSelectorSolver,
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										DNSZones: []string{"com"},
									},
									HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
										Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
											Name: "com-dnszone-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  exampleComDNSNameSelectorSolver,
			},
		},
		"dnsName selectors should take precedence over dnsZone selectors (reversed order)": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										DNSZones: []string{"com"},
									},
									DNS01: &cmacme.ACMEChallengeSolverDNS01{
										Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
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
			order: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  exampleComDNSNameSelectorSolver,
			},
		},
		"should allow matching with dnsZones": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								emptySelectorSolverDNS01,
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										DNSZones: []string{"example.com"},
									},
									DNS01: &cmacme.ACMEChallengeSolverDNS01{
										Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
											Email: "example-com-dnszone-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"www.example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "www.example.com",
				Wildcard:   pointer.BoolPtr(true),
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeDNS01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:     cmacme.ACMEChallengeTypeDNS01,
				DNSName:  "www.example.com",
				Wildcard: true,
				Token:    acmeChallengeDNS01.Token,
				Key:      "dns01",
				Solver: cmacme.ACMEChallengeSolver{
					Selector: &cmacme.CertificateDNSNameSelector{
						DNSZones: []string{"example.com"},
					},
					DNS01: &cmacme.ACMEChallengeSolverDNS01{
						Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
							Email: "example-com-dnszone-selector-solver",
						},
					},
				},
			},
		},
		"most specific dnsZone should be selected if multiple match": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										DNSZones: []string{"example.com"},
									},
									DNS01: &cmacme.ACMEChallengeSolverDNS01{
										Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
											Email: "example-com-dnszone-selector-solver",
										},
									},
								},
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										DNSZones: []string{"prod.example.com"},
									},
									DNS01: &cmacme.ACMEChallengeSolverDNS01{
										Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
											Email: "prod-example-com-dnszone-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"www.prod.example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "www.prod.example.com",
				Wildcard:   pointer.BoolPtr(true),
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeDNS01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:     cmacme.ACMEChallengeTypeDNS01,
				DNSName:  "www.prod.example.com",
				Wildcard: true,
				Token:    acmeChallengeDNS01.Token,
				Key:      "dns01",
				Solver: cmacme.ACMEChallengeSolver{
					Selector: &cmacme.CertificateDNSNameSelector{
						DNSZones: []string{"prod.example.com"},
					},
					DNS01: &cmacme.ACMEChallengeSolverDNS01{
						Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
							Email: "prod-example-com-dnszone-selector-solver",
						},
					},
				},
			},
		},
		"most specific dnsZone should be selected if multiple match (reversed)": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										DNSZones: []string{"prod.example.com"},
									},
									DNS01: &cmacme.ACMEChallengeSolverDNS01{
										Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
											Email: "prod-example-com-dnszone-selector-solver",
										},
									},
								},
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										DNSZones: []string{"example.com"},
									},
									DNS01: &cmacme.ACMEChallengeSolverDNS01{
										Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
											Email: "example-com-dnszone-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"www.prod.example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "www.prod.example.com",
				Wildcard:   pointer.BoolPtr(true),
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeDNS01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:     cmacme.ACMEChallengeTypeDNS01,
				DNSName:  "www.prod.example.com",
				Wildcard: true,
				Token:    acmeChallengeDNS01.Token,
				Key:      "dns01",
				Solver: cmacme.ACMEChallengeSolver{
					Selector: &cmacme.CertificateDNSNameSelector{
						DNSZones: []string{"prod.example.com"},
					},
					DNS01: &cmacme.ACMEChallengeSolverDNS01{
						Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
							Email: "prod-example-com-dnszone-selector-solver",
						},
					},
				},
			},
		},
		"if two solvers specify the same dnsZone, the one with the most labels should be chosen": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										DNSZones: []string{"example.com"},
									},
									HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
										Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-dnszone-selector-solver",
										},
									},
								},
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										MatchLabels: map[string]string{
											"label": "exists",
										},
										DNSZones: []string{"example.com"},
									},
									HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
										Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-dnszone-labels-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"label": "exists",
					},
				},
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"www.example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "www.example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "www.example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver: cmacme.ACMEChallengeSolver{
					Selector: &cmacme.CertificateDNSNameSelector{
						MatchLabels: map[string]string{
							"label": "exists",
						},
						DNSZones: []string{"example.com"},
					},
					HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
						Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
							Name: "example-com-dnszone-labels-selector-solver",
						},
					},
				},
			},
		},
		"if both solvers match dnsNames, and one also matches dnsZones, choose the one that matches dnsZones": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										DNSNames: []string{"www.example.com"},
									},
									HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
										Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-dnsname-selector-solver",
										},
									},
								},
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										DNSZones: []string{"example.com"},
										DNSNames: []string{"www.example.com"},
									},
									HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
										Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-dnsname-dnszone-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"www.example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "www.example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "www.example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver: cmacme.ACMEChallengeSolver{
					Selector: &cmacme.CertificateDNSNameSelector{
						DNSZones: []string{"example.com"},
						DNSNames: []string{"www.example.com"},
					},
					HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
						Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
							Name: "example-com-dnsname-dnszone-selector-solver",
						},
					},
				},
			},
		},
		"if both solvers match dnsNames, and one also matches dnsZones, choose the one that matches dnsZones (reversed)": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										DNSZones: []string{"example.com"},
										DNSNames: []string{"www.example.com"},
									},
									HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
										Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-dnsname-dnszone-selector-solver",
										},
									},
								},
								{
									Selector: &cmacme.CertificateDNSNameSelector{
										DNSNames: []string{"www.example.com"},
									},
									HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
										Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
											Name: "example-com-dnsname-selector-solver",
										},
									},
								},
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"www.example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "www.example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "www.example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver: cmacme.ACMEChallengeSolver{
					Selector: &cmacme.CertificateDNSNameSelector{
						DNSZones: []string{"example.com"},
						DNSNames: []string{"www.example.com"},
					},
					HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
						Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
							Name: "example-com-dnsname-dnszone-selector-solver",
						},
					},
				},
			},
		},
		"uses correct solver when selector explicitly names dnsName (reversed)": {
			acmeClient: basicACMEClient,
			issuer: &v1.Issuer{
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								exampleComDNSNameSelectorSolver,
								emptySelectorSolverHTTP01,
							},
						},
					},
				},
			},
			order: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					DNSNames: []string{"example.com"},
				},
			},
			authz: &cmacme.ACMEAuthorization{
				Identifier: "example.com",
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeHTTP01},
			},
			expectedChallengeSpec: &cmacme.ChallengeSpec{
				Type:    cmacme.ACMEChallengeTypeHTTP01,
				DNSName: "example.com",
				Token:   acmeChallengeHTTP01.Token,
				Key:     "http01",
				Solver:  exampleComDNSNameSelectorSolver,
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cs, err := challengeSpecForAuthorization(ctx, test.acmeClient, test.issuer, test.order, *test.authz)
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
