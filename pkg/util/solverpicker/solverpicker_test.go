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

package solverpicker

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func TestPick(t *testing.T) {
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
		issuer            cmapi.GenericIssuer
		order             *cmacme.Order
		authz             *cmacme.ACMEAuthorization
		expectedSolver    *cmacme.ACMEChallengeSolver
		expectedChallenge *cmacme.ACMEChallenge
	}{
		"should use configured default solver when no others are present": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver:    &emptySelectorSolverHTTP01,
			expectedChallenge: acmeChallengeHTTP01,
		},
		"should use configured default solver when no others are present but selector is non-nil": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver: &cmacme.ACMEChallengeSolver{
				Selector: &cmacme.CertificateDNSNameSelector{},
				HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
					Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
						Name: "empty-selector-solver",
					},
				},
			},
			expectedChallenge: acmeChallengeHTTP01,
		},
		"should use configured default solver when others do not match": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver:    &emptySelectorSolverHTTP01,
			expectedChallenge: acmeChallengeHTTP01,
		},
		"should use DNS01 solver over HTTP01 if challenge is of type DNS01": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver:    &emptySelectorSolverDNS01,
			expectedChallenge: acmeChallengeDNS01,
		},
		"should return nil if none match": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver:    nil,
			expectedChallenge: nil,
		},
		"uses correct solver when selector explicitly names dnsName": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver:    &exampleComDNSNameSelectorSolver,
			expectedChallenge: acmeChallengeHTTP01,
		},
		"uses default solver if dnsName does not match": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver:    &emptySelectorSolverHTTP01,
			expectedChallenge: acmeChallengeHTTP01,
		},
		"if two solvers specify the same dnsName, the one with the most labels should be chosen": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver: &cmacme.ACMEChallengeSolver{
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
			expectedChallenge: acmeChallengeHTTP01,
		},
		"if one solver matches with dnsNames, and the other solver matches with labels, the dnsName solver should be chosen": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver:    &exampleComDNSNameSelectorSolver,
			expectedChallenge: acmeChallengeHTTP01,
		},
		// identical to the test above, but the solvers are listed in reverse
		// order to ensure that this behaviour isn't just incidental
		"if one solver matches with dnsNames, and the other solver matches with labels, the dnsName solver should be chosen (solvers listed in reverse order)": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver:    &exampleComDNSNameSelectorSolver,
			expectedChallenge: acmeChallengeHTTP01,
		},
		"if one solver matches with dnsNames, and the other solver matches with 2 labels, the dnsName solver should be chosen": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver:    &exampleComDNSNameSelectorSolver,
			expectedChallenge: acmeChallengeHTTP01,
		},
		"should choose the solver with the most labels matching if multiple match": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver: &cmacme.ACMEChallengeSolver{
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
			expectedChallenge: acmeChallengeHTTP01,
		},
		"should match wildcard dnsName solver if authorization has Wildcard=true": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
				Wildcard:   ptr.To(true),
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeDNS01},
			},
			expectedSolver: &cmacme.ACMEChallengeSolver{
				Selector: &cmacme.CertificateDNSNameSelector{
					DNSNames: []string{"*.example.com"},
				},
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
						Email: "example-com-wc-dnsname-selector-solver",
					},
				},
			},
			expectedChallenge: acmeChallengeDNS01,
		},
		"dnsName selectors should take precedence over dnsZone selectors": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver:    &exampleComDNSNameSelectorSolver,
			expectedChallenge: acmeChallengeHTTP01,
		},
		"dnsName selectors should take precedence over dnsZone selectors (reversed order)": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver:    &exampleComDNSNameSelectorSolver,
			expectedChallenge: acmeChallengeHTTP01,
		},
		"should allow matching with dnsZones": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
				Wildcard:   ptr.To(true),
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeDNS01},
			},
			expectedSolver: &cmacme.ACMEChallengeSolver{
				Selector: &cmacme.CertificateDNSNameSelector{
					DNSZones: []string{"example.com"},
				},
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
						Email: "example-com-dnszone-selector-solver",
					},
				},
			},
			expectedChallenge: acmeChallengeDNS01,
		},
		"most specific dnsZone should be selected if multiple match": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
				Wildcard:   ptr.To(true),
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeDNS01},
			},
			expectedSolver: &cmacme.ACMEChallengeSolver{
				Selector: &cmacme.CertificateDNSNameSelector{
					DNSZones: []string{"prod.example.com"},
				},
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
						Email: "prod-example-com-dnszone-selector-solver",
					},
				},
			},
			expectedChallenge: acmeChallengeDNS01,
		},
		"most specific dnsZone should be selected if multiple match (reversed)": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
				Wildcard:   ptr.To(true),
				Challenges: []cmacme.ACMEChallenge{*acmeChallengeDNS01},
			},
			expectedSolver: &cmacme.ACMEChallengeSolver{
				Selector: &cmacme.CertificateDNSNameSelector{
					DNSZones: []string{"prod.example.com"},
				},
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
						Email: "prod-example-com-dnszone-selector-solver",
					},
				},
			},
			expectedChallenge: acmeChallengeDNS01,
		},
		"if two solvers specify the same dnsZone, the one with the most labels should be chosen": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver: &cmacme.ACMEChallengeSolver{
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
			expectedChallenge: acmeChallengeHTTP01,
		},
		"if both solvers match dnsNames, and one also matches dnsZones, choose the one that matches dnsZones": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver: &cmacme.ACMEChallengeSolver{
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
			expectedChallenge: acmeChallengeHTTP01,
		},
		"if both solvers match dnsNames, and one also matches dnsZones, choose the one that matches dnsZones (reversed)": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver: &cmacme.ACMEChallengeSolver{
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
			expectedChallenge: acmeChallengeHTTP01,
		},
		"uses correct solver when selector explicitly names dnsName (reversed)": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
			expectedSolver:    &exampleComDNSNameSelectorSolver,
			expectedChallenge: acmeChallengeHTTP01,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			domainToFind := test.authz.Identifier
			if test.authz.Wildcard != nil {
				domainToFind = "*." + domainToFind
			}

			solver, ch := Pick(t.Context(), domainToFind, test.authz.Challenges, test.issuer.GetSpec().ACME.Solvers, test.order)

			if !reflect.DeepEqual(test.expectedSolver, solver) {
				t.Errorf("expected solver %v, got %v", test.expectedSolver, solver)
			}

			if !reflect.DeepEqual(test.expectedChallenge, ch) {
				t.Errorf("expected challenge token %v, got %v", test.expectedChallenge, ch)
			}
		})
	}
}
