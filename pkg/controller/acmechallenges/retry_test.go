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

package acmechallenges

import (
	"testing"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

func TestShouldReattemptRequest_Table(t *testing.T) {
	r := &retrySolver{}

	tests := []struct {
		name string
		orig cmacme.ACMEChallengeSolver
		newS cmacme.ACMEChallengeSolver
		want bool
	}{
		{
			name: "DigitalOcean token ref changed (name) -> true",
			orig: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					DigitalOcean: &cmacme.ACMEIssuerDNS01ProviderDigitalOcean{
						Token: cmmetav1.SecretKeySelector{
							LocalObjectReference: cmmetav1.LocalObjectReference{Name: "do-secret-a"},
							Key:                  "token",
						},
					},
				},
			},
			newS: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					DigitalOcean: &cmacme.ACMEIssuerDNS01ProviderDigitalOcean{
						Token: cmmetav1.SecretKeySelector{
							LocalObjectReference: cmmetav1.LocalObjectReference{Name: "do-secret-b"},
							Key:                  "token",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "DigitalOcean token ref changed (key) -> true",
			orig: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					DigitalOcean: &cmacme.ACMEIssuerDNS01ProviderDigitalOcean{
						Token: cmmetav1.SecretKeySelector{
							LocalObjectReference: cmmetav1.LocalObjectReference{Name: "do-secret"},
							Key:                  "tokenA",
						},
					},
				},
			},
			newS: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					DigitalOcean: &cmacme.ACMEIssuerDNS01ProviderDigitalOcean{
						Token: cmmetav1.SecretKeySelector{
							LocalObjectReference: cmmetav1.LocalObjectReference{Name: "do-secret"},
							Key:                  "tokenB",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "DigitalOcean token ref same -> false",
			orig: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					DigitalOcean: &cmacme.ACMEIssuerDNS01ProviderDigitalOcean{
						Token: cmmetav1.SecretKeySelector{
							LocalObjectReference: cmmetav1.LocalObjectReference{Name: "do-secret"},
							Key:                  "token",
						},
					},
				},
			},
			newS: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					DigitalOcean: &cmacme.ACMEIssuerDNS01ProviderDigitalOcean{
						Token: cmmetav1.SecretKeySelector{
							LocalObjectReference: cmmetav1.LocalObjectReference{Name: "do-secret"},
							Key:                  "token",
						},
					},
				},
			},
			want: false,
		},
		{
			name: "DigitalOcean present only on orig -> false",
			orig: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					DigitalOcean: &cmacme.ACMEIssuerDNS01ProviderDigitalOcean{
						Token: cmmetav1.SecretKeySelector{
							LocalObjectReference: cmmetav1.LocalObjectReference{Name: "do-secret"},
							Key:                  "token",
						},
					},
				},
			},
			newS: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{},
			},
			want: false,
		},
		{
			name: "DigitalOcean present only on new -> false",
			orig: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{},
			},
			newS: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					DigitalOcean: &cmacme.ACMEIssuerDNS01ProviderDigitalOcean{
						Token: cmmetav1.SecretKeySelector{
							LocalObjectReference: cmmetav1.LocalObjectReference{Name: "do-secret"},
							Key:                  "token",
						},
					},
				},
			},
			want: false,
		},
		{
			name: "Route53 equal -> false",
			orig: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
						Region: "us-east-1",
					},
				},
			},
			newS: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
						Region: "us-east-1",
					},
				},
			},
			want: false,
		},
		{
			name: "Route53 different -> true",
			orig: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
						Region: "us-east-1",
					},
				},
			},
			newS: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
						Region: "eu-west-1",
					},
				},
			},
			want: true,
		},
		{
			name: "Route53 present only on orig -> false",
			orig: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
						Region: "us-east-1",
					},
				},
			},
			newS: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{},
			},
			want: false,
		},
		{
			name: "Route53 present only on new -> false",
			orig: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{},
			},
			newS: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
						Region: "us-east-1",
					},
				},
			},
			want: false,
		},
		{
			name: "Both providers absent (DNS01 present) -> false",
			orig: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{},
			},
			newS: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{},
			},
			want: false,
		},
		{
			name: "Both providers present; DO token ref same; Route53 different -> false (DO branch short-circuits)",
			orig: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					DigitalOcean: &cmacme.ACMEIssuerDNS01ProviderDigitalOcean{
						Token: cmmetav1.SecretKeySelector{
							LocalObjectReference: cmmetav1.LocalObjectReference{Name: "do-secret"},
							Key:                  "token",
						},
					},
					Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
						Region: "us-east-1",
					},
				},
			},
			newS: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					DigitalOcean: &cmacme.ACMEIssuerDNS01ProviderDigitalOcean{
						Token: cmmetav1.SecretKeySelector{
							LocalObjectReference: cmmetav1.LocalObjectReference{Name: "do-secret"},
							Key:                  "token",
						},
					},
					Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
						Region: "eu-west-1",
					},
				},
			},
			want: false,
		},
		{
			name: "Both providers present; DO token ref different; Route53 equal -> true (DO branch decides)",
			orig: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					DigitalOcean: &cmacme.ACMEIssuerDNS01ProviderDigitalOcean{
						Token: cmmetav1.SecretKeySelector{
							LocalObjectReference: cmmetav1.LocalObjectReference{Name: "do-secret-a"},
							Key:                  "token",
						},
					},
					Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
						Region: "us-east-1",
					},
				},
			},
			newS: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					DigitalOcean: &cmacme.ACMEIssuerDNS01ProviderDigitalOcean{
						Token: cmmetav1.SecretKeySelector{
							LocalObjectReference: cmmetav1.LocalObjectReference{Name: "do-secret-b"},
							Key:                  "token",
						},
					},
					Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
						Region: "us-east-1",
					},
				},
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Keep DNS01 non-nil to match function preconditions
			if tc.orig.DNS01 == nil || tc.newS.DNS01 == nil {
				t.Fatalf("test %q must set DNS01 to non-nil", tc.name)
			}
			got := r.shouldRetry(cmmetav1.IssuerReference{}, tc.orig, tc.newS)
			if got != tc.want {
				t.Fatalf("shouldRetry() = %v, want %v", got, tc.want)
			}
		})
	}
}
