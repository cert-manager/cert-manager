/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package acme

import (
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/util/diff"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/third_party/crypto/acme"
)

const (
	defaultTestNamespace = "default"
)

func TestSolverConfigurationForAuthorization(t *testing.T) {
	type testT struct {
		cfg         *v1alpha1.ACMECertificateConfig
		authz       *acme.Authorization
		expectedCfg *v1alpha1.SolverConfig
		expectedErr bool
	}
	tests := map[string]testT{
		"correctly selects normal domain": testT{
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.DomainSolverConfig{
					{
						Domains: []string{"example.com"},
						SolverConfig: v1alpha1.SolverConfig{
							DNS01: &v1alpha1.DNS01SolverConfig{
								Provider: "correctdns",
							},
						},
					},
				},
			},
			authz: &acme.Authorization{
				Identifier: acme.AuthzID{
					Value: "example.com",
				},
			},
			expectedCfg: &v1alpha1.SolverConfig{
				DNS01: &v1alpha1.DNS01SolverConfig{
					Provider: "correctdns",
				},
			},
		},
		"correctly selects normal domain with multiple domains configured": testT{
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.DomainSolverConfig{
					{
						Domains: []string{"notexample.com", "example.com"},
						SolverConfig: v1alpha1.SolverConfig{
							DNS01: &v1alpha1.DNS01SolverConfig{
								Provider: "correctdns",
							},
						},
					},
				},
			},
			authz: &acme.Authorization{
				Identifier: acme.AuthzID{
					Value: "example.com",
				},
			},
			expectedCfg: &v1alpha1.SolverConfig{
				DNS01: &v1alpha1.DNS01SolverConfig{
					Provider: "correctdns",
				},
			},
		},
		"correctly selects normal domain with multiple domains configured separately": testT{
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.DomainSolverConfig{
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
			},
			authz: &acme.Authorization{
				Identifier: acme.AuthzID{
					Value: "example.com",
				},
			},
			expectedCfg: &v1alpha1.SolverConfig{
				DNS01: &v1alpha1.DNS01SolverConfig{
					Provider: "correctdns",
				},
			},
		},
		"correctly selects configuration for wildcard domain": testT{
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.DomainSolverConfig{
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
			},
			authz: &acme.Authorization{
				Wildcard: true,
				Identifier: acme.AuthzID{
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
		"returns an error when configuration for the domain is not found": testT{
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.DomainSolverConfig{
					{
						Domains: []string{"notexample.com"},
						SolverConfig: v1alpha1.SolverConfig{
							DNS01: &v1alpha1.DNS01SolverConfig{
								Provider: "incorrectdns",
							},
						},
					},
				},
			},
			authz: &acme.Authorization{
				Identifier: acme.AuthzID{
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
