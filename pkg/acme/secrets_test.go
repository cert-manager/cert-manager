/*
Copyright 2026 The cert-manager Authors.

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

package acme_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cert-manager/cert-manager/pkg/acme"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestRequiredDNS01SolverSecrets(t *testing.T) {
	// RequiredDNS01SolverSecrets can only return an error if api.Scheme.Convert
	// fails converting the external ACMEChallengeSolver to its internal type.
	// That conversion is entirely generated field-copying (no parsing or
	// validation), so it cannot fail for any value of the external Go struct
	// type - there is no test case for it here because there is no reachable
	// way to construct one.
	tests := map[string]struct {
		issuer        gen.IssuerModifier
		expectNames   []string
		expectNoSlice bool
	}{
		"non-ACME issuer returns no secrets": {
			issuer:        gen.SetIssuerCA(v1.CAIssuer{SecretName: "ca-secret"}),
			expectNoSlice: true,
		},
		"ACME issuer with no solvers returns no secrets": {
			issuer:      gen.SetIssuerACME(cmacme.ACMEIssuer{}),
			expectNames: nil,
		},
		"ACME issuer with an HTTP-01-only solver returns no secrets": {
			issuer: gen.SetIssuerACMESolvers([]cmacme.ACMEChallengeSolver{
				{HTTP01: &cmacme.ACMEChallengeSolverHTTP01{}},
			}),
			expectNames: nil,
		},
		"ACME issuer with a Route53 DNS-01 solver returns its secret": {
			issuer: gen.SetIssuerACMESolvers([]cmacme.ACMEChallengeSolver{
				{DNS01: &cmacme.ACMEChallengeSolverDNS01{
					Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
						SecretAccessKey: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{Name: "route53-creds"},
							Key:                  "secret-access-key",
						},
					},
				}},
			}),
			expectNames: []string{"route53-creds"},
		},
		"ACME issuer with an Akamai DNS-01 solver returns its secrets": {
			issuer: gen.SetIssuerACMESolvers([]cmacme.ACMEChallengeSolver{
				{DNS01: &cmacme.ACMEChallengeSolverDNS01{
					Akamai: &cmacme.ACMEIssuerDNS01ProviderAkamai{
						ServiceConsumerDomain: "example.com",
						AccessToken:           cmmeta.SecretKeySelector{LocalObjectReference: cmmeta.LocalObjectReference{Name: "akamai-access-token"}},
						ClientSecret:          cmmeta.SecretKeySelector{LocalObjectReference: cmmeta.LocalObjectReference{Name: "akamai-client-secret"}},
						ClientToken:           cmmeta.SecretKeySelector{LocalObjectReference: cmmeta.LocalObjectReference{Name: "akamai-client-token"}},
					},
				}},
			}),
			expectNames: []string{"akamai-access-token", "akamai-client-secret", "akamai-client-token"},
		},
		"ACME issuer with an AzureDNS DNS-01 solver returns its secret": {
			issuer: gen.SetIssuerACMESolvers([]cmacme.ACMEChallengeSolver{
				{DNS01: &cmacme.ACMEChallengeSolverDNS01{
					AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
						ClientSecret: &cmmeta.SecretKeySelector{LocalObjectReference: cmmeta.LocalObjectReference{Name: "azuredns-creds"}},
					},
				}},
			}),
			expectNames: []string{"azuredns-creds"},
		},
		"ACME issuer with a Cloudflare DNS-01 solver returns its secret": {
			issuer: gen.SetIssuerACMESolvers([]cmacme.ACMEChallengeSolver{
				{DNS01: &cmacme.ACMEChallengeSolverDNS01{
					Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
						APIToken: &cmmeta.SecretKeySelector{LocalObjectReference: cmmeta.LocalObjectReference{Name: "cloudflare-token"}},
					},
				}},
			}),
			expectNames: []string{"cloudflare-token"},
		},
		"ACME issuer with an AcmeDNS DNS-01 solver returns its secret": {
			issuer: gen.SetIssuerACMESolvers([]cmacme.ACMEChallengeSolver{
				{DNS01: &cmacme.ACMEChallengeSolverDNS01{
					AcmeDNS: &cmacme.ACMEIssuerDNS01ProviderAcmeDNS{
						Host:          "https://auth.example.com",
						AccountSecret: cmmeta.SecretKeySelector{LocalObjectReference: cmmeta.LocalObjectReference{Name: "acmedns-creds"}},
					},
				}},
			}),
			expectNames: []string{"acmedns-creds"},
		},
		"ACME issuer with a DigitalOcean DNS-01 solver returns its secret": {
			issuer: gen.SetIssuerACMESolvers([]cmacme.ACMEChallengeSolver{
				{DNS01: &cmacme.ACMEChallengeSolverDNS01{
					DigitalOcean: &cmacme.ACMEIssuerDNS01ProviderDigitalOcean{
						Token: cmmeta.SecretKeySelector{LocalObjectReference: cmmeta.LocalObjectReference{Name: "digitalocean-token"}},
					},
				}},
			}),
			expectNames: []string{"digitalocean-token"},
		},
		"ACME issuer with an RFC2136 DNS-01 solver returns its secret": {
			issuer: gen.SetIssuerACMESolvers([]cmacme.ACMEChallengeSolver{
				{DNS01: &cmacme.ACMEChallengeSolverDNS01{
					RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
						Nameserver: "ns.example.com:53",
						TSIGSecret: cmmeta.SecretKeySelector{LocalObjectReference: cmmeta.LocalObjectReference{Name: "rfc2136-tsig"}},
					},
				}},
			}),
			expectNames: []string{"rfc2136-tsig"},
		},
		"ACME issuer with multiple DNS-01 solvers returns all their secrets": {
			issuer: gen.SetIssuerACMESolvers([]cmacme.ACMEChallengeSolver{
				{DNS01: &cmacme.ACMEChallengeSolverDNS01{
					Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
						SecretAccessKey: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{Name: "route53-creds"},
							Key:                  "secret-access-key",
						},
					},
				}},
				{DNS01: &cmacme.ACMEChallengeSolverDNS01{
					CloudDNS: &cmacme.ACMEIssuerDNS01ProviderCloudDNS{
						ServiceAccount: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{Name: "clouddns-creds"},
							Key:                  "service-account.json",
						},
					},
				}},
			}),
			expectNames: []string{"route53-creds", "clouddns-creds"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			issuer := gen.Issuer("test", tc.issuer)

			secrets, err := acme.RequiredDNS01SolverSecrets(issuer)
			require.NoError(t, err)

			if tc.expectNoSlice {
				assert.Nil(t, secrets)
				return
			}

			var names []string
			for _, s := range secrets {
				names = append(names, s.Name)
			}
			assert.Equal(t, tc.expectNames, names)
		})
	}
}
