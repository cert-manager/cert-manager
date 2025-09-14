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
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
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
		issuer     cmapi.GenericIssuer
		order      *cmacme.Order
		authz      *cmacme.ACMEAuthorization

		expectedChallengeSpec *cmacme.ChallengeSpec
		expectedError         bool
	}{
		"should override the ingress name to edit if override annotation is specified": {
			acmeClient: basicACMEClient,
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
				Solver: cmacme.ACMEChallengeSolver{
					HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
						Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
							Class: ptr.To("test-class-to-override"),
						},
					},
				},
			},
		},
		"should return an error if both ingress class and name override annotations are set": {
			acmeClient: basicACMEClient,
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
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
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
				Solver:  emptySelectorSolverDNS01,
			},
		},
		"should return an error if none match": {
			issuer: &cmapi.Issuer{
				Spec: cmapi.IssuerSpec{
					IssuerConfig: cmapi.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Solvers: []cmacme.ACMEChallengeSolver{
								{
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
			expectedError: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cs, err := partialChallengeSpecForAuthorization(t.Context(), test.issuer, test.order, *test.authz)
			if err != nil && !test.expectedError {
				t.Errorf("expected to not get an error, but got: %v", err)
				t.Fail()
			}
			if err == nil && test.expectedError {
				t.Errorf("expected to get an error, but got none")
			}
			if !reflect.DeepEqual(cs, test.expectedChallengeSpec) {
				t.Errorf("returned challenge spec was not as expected (-want +got):\n%s", cmp.Diff(test.expectedChallengeSpec, cs))
			}
		})
	}
}

func Test_ensureKeysForChallenges(t *testing.T) {
	basicACMEClient := &acmecl.FakeACME{
		FakeHTTP01ChallengeResponse: func(token string) (string, error) {
			switch token {
			case "fooToken":
				return "fooKeyHTTP01", nil
			case "barToken":
				return "barKeyHTTP01", nil
			}
			return "", fmt.Errorf("internal error: unexpected token value %s", token)
		},
		FakeDNS01ChallengeRecord: func(token string) (string, error) {
			switch token {
			case "fooToken":
				return "fooKeyDNS01", nil
			case "barToken":
				return "barKeyDNS01", nil
			}
			return "", fmt.Errorf("internal error: unexpected token value %s", token)
		},
	}
	fooChallenge := gen.Challenge("foo", gen.SetChallengeToken("fooToken"))
	barChallenge := gen.Challenge("bar", gen.SetChallengeToken("barToken"))
	tests := map[string]struct {
		acmeClient        acmecl.Interface
		partialChallenges []*cmacme.Challenge
		want              []*cmacme.Challenge
		wantErr           bool
	}{
		"happy path with some http-01 challenges": {
			acmeClient: basicACMEClient,
			partialChallenges: []*cmacme.Challenge{
				gen.ChallengeFrom(fooChallenge, gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01)),
				gen.ChallengeFrom(barChallenge, gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01))},
			want: []*cmacme.Challenge{
				gen.ChallengeFrom(fooChallenge, gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
					gen.SetChallengeKey("fooKeyHTTP01")),
				gen.ChallengeFrom(barChallenge, gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
					gen.SetChallengeKey("barKeyHTTP01"))},
		},
		"happy path with some dns-01 challenges": {
			acmeClient: basicACMEClient,
			partialChallenges: []*cmacme.Challenge{
				gen.ChallengeFrom(fooChallenge, gen.SetChallengeType(cmacme.ACMEChallengeTypeDNS01)),
				gen.ChallengeFrom(barChallenge, gen.SetChallengeType(cmacme.ACMEChallengeTypeDNS01))},
			want: []*cmacme.Challenge{
				gen.ChallengeFrom(fooChallenge, gen.SetChallengeType(cmacme.ACMEChallengeTypeDNS01),
					gen.SetChallengeKey("fooKeyDNS01")),
				gen.ChallengeFrom(barChallenge, gen.SetChallengeType(cmacme.ACMEChallengeTypeDNS01),
					gen.SetChallengeKey("barKeyDNS01"))},
		},
		"unhappy path with an unknown challenge type": {
			acmeClient:        basicACMEClient,
			partialChallenges: []*cmacme.Challenge{gen.ChallengeFrom(fooChallenge, gen.SetChallengeType(cmacme.ACMEChallengeType("foo")))},
			wantErr:           true,
		},
	}
	for name, scenario := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ensureKeysForChallenges(scenario.acmeClient, scenario.partialChallenges)
			if (err != nil) != scenario.wantErr {
				t.Errorf("ensureKeysForChallenges() error = %v, wantErr %v", err, scenario.wantErr)
				return
			}
			if !reflect.DeepEqual(got, scenario.want) {
				t.Errorf("ensureKeysForChallenges() = %v, want %v", got, scenario.want)
			}
		})
	}
}
