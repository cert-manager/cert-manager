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

package clusterissuers

import (
	"testing"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

func TestACMEIssuerReferencesSecret(t *testing.T) {
	solverSecret := "dns-solver-creds"
	eabSecret := "eab-creds"
	accountSecret := "account-key"

	tests := []struct {
		name       string
		acme       *cmacme.ACMEIssuer
		secretName string
		want       bool
	}{
		{
			name: "private key",
			acme: &cmacme.ACMEIssuer{
				PrivateKey: cmmeta.SecretKeySelector{LocalObjectReference: cmmeta.LocalObjectReference{Name: accountSecret}},
			},
			secretName: accountSecret,
			want:       true,
		},
		{
			name: "eab key",
			acme: &cmacme.ACMEIssuer{
				PrivateKey: cmmeta.SecretKeySelector{LocalObjectReference: cmmeta.LocalObjectReference{Name: accountSecret}},
				ExternalAccountBinding: &cmacme.ACMEExternalAccountBinding{
					Key: cmmeta.SecretKeySelector{LocalObjectReference: cmmeta.LocalObjectReference{Name: eabSecret}},
				},
			},
			secretName: eabSecret,
			want:       true,
		},
		{
			name: "route53 solver secret",
			acme: &cmacme.ACMEIssuer{
				PrivateKey: cmmeta.SecretKeySelector{LocalObjectReference: cmmeta.LocalObjectReference{Name: accountSecret}},
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						DNS01: &cmacme.ACMEChallengeSolverDNS01{
							Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
								SecretAccessKey: cmmeta.SecretKeySelector{
									LocalObjectReference: cmmeta.LocalObjectReference{Name: solverSecret},
									Key:                  "secret-access-key",
								},
							},
						},
					},
				},
			},
			secretName: solverSecret,
			want:       true,
		},
		{
			name: "clouddns solver secret",
			acme: &cmacme.ACMEIssuer{
				PrivateKey: cmmeta.SecretKeySelector{LocalObjectReference: cmmeta.LocalObjectReference{Name: accountSecret}},
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						DNS01: &cmacme.ACMEChallengeSolverDNS01{
							CloudDNS: &cmacme.ACMEIssuerDNS01ProviderCloudDNS{
								ServiceAccount: &cmmeta.SecretKeySelector{
									LocalObjectReference: cmmeta.LocalObjectReference{Name: solverSecret},
									Key:                  "key.json",
								},
							},
						},
					},
				},
			},
			secretName: solverSecret,
			want:       true,
		},
		{
			name: "unrelated secret",
			acme: &cmacme.ACMEIssuer{
				PrivateKey: cmmeta.SecretKeySelector{LocalObjectReference: cmmeta.LocalObjectReference{Name: accountSecret}},
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						DNS01: &cmacme.ACMEChallengeSolverDNS01{
							Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
								SecretAccessKey: cmmeta.SecretKeySelector{
									LocalObjectReference: cmmeta.LocalObjectReference{Name: solverSecret},
								},
							},
						},
					},
				},
			},
			secretName: "other",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := acmeIssuerReferencesSecret(tt.acme, tt.secretName); got != tt.want {
				t.Fatalf("acmeIssuerReferencesSecret() = %v, want %v", got, tt.want)
			}
		})
	}
}
