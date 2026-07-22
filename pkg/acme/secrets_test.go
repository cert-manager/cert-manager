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
	tests := map[string]struct {
		issuer        gen.IssuerModifier
		expectNames   []string
		expectErr     bool
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
			if tc.expectErr {
				require.Error(t, err)
				return
			}
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
