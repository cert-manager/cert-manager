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

func TestACMESolverConfigurationForAuthorization(t *testing.T) {
	type testT struct {
		cfg         *v1alpha1.ACMECertificateConfig
		authz       *acme.Authorization
		expectedCfg *v1alpha1.ACMESolverConfig
		expectedErr bool
	}
	tests := map[string]testT{
		"correctly selects normal domain": testT{
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.ACMECertificateDomainConfig{
					{
						Domains: []string{"example.com"},
						ACMESolverConfig: v1alpha1.ACMESolverConfig{
							DNS01: &v1alpha1.ACMECertificateDNS01Config{
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
			expectedCfg: &v1alpha1.ACMESolverConfig{
				DNS01: &v1alpha1.ACMECertificateDNS01Config{
					Provider: "correctdns",
				},
			},
		},
		"correctly selects normal domain with multiple domains configured": testT{
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.ACMECertificateDomainConfig{
					{
						Domains: []string{"notexample.com", "example.com"},
						ACMESolverConfig: v1alpha1.ACMESolverConfig{
							DNS01: &v1alpha1.ACMECertificateDNS01Config{
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
			expectedCfg: &v1alpha1.ACMESolverConfig{
				DNS01: &v1alpha1.ACMECertificateDNS01Config{
					Provider: "correctdns",
				},
			},
		},
		"correctly selects normal domain with multiple domains configured separately": testT{
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.ACMECertificateDomainConfig{
					{
						Domains: []string{"example.com"},
						ACMESolverConfig: v1alpha1.ACMESolverConfig{
							DNS01: &v1alpha1.ACMECertificateDNS01Config{
								Provider: "correctdns",
							},
						},
					},
					{
						Domains: []string{"notexample.com"},
						ACMESolverConfig: v1alpha1.ACMESolverConfig{
							DNS01: &v1alpha1.ACMECertificateDNS01Config{
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
			expectedCfg: &v1alpha1.ACMESolverConfig{
				DNS01: &v1alpha1.ACMECertificateDNS01Config{
					Provider: "correctdns",
				},
			},
		},
		"correctly selects configuration for wildcard domain": testT{
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.ACMECertificateDomainConfig{
					{
						Domains: []string{"example.com"},
						ACMESolverConfig: v1alpha1.ACMESolverConfig{
							DNS01: &v1alpha1.ACMECertificateDNS01Config{
								Provider: "incorrectdns",
							},
						},
					},
					{
						Domains: []string{"*.example.com"},
						ACMESolverConfig: v1alpha1.ACMESolverConfig{
							DNS01: &v1alpha1.ACMECertificateDNS01Config{
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
			expectedCfg: &v1alpha1.ACMESolverConfig{
				DNS01: &v1alpha1.ACMECertificateDNS01Config{
					Provider: "correctdns",
				},
			},
		},
		"returns an error when configuration for the domain is not found": testT{
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.ACMECertificateDomainConfig{
					{
						Domains: []string{"notexample.com"},
						ACMESolverConfig: v1alpha1.ACMESolverConfig{
							DNS01: &v1alpha1.ACMECertificateDNS01Config{
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
			actualCfg, err := acmeSolverConfigurationForAuthorization(test.cfg, test.authz)
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
