package dns

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/cloudflare"
)

func newIssuer(name, namespace string, configs []v1alpha1.ACMEIssuerDNS01Provider) *v1alpha1.Issuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				ACME: &v1alpha1.ACMEIssuer{
					DNS01: &v1alpha1.ACMEIssuerDNS01Config{
						Providers: configs,
					},
				},
			},
		},
	}
}

func newCertificate(name, namespace, cn string, dnsNames []string, configs []v1alpha1.DomainSolverConfig) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		Spec: v1alpha1.CertificateSpec{
			CommonName: cn,
			DNSNames:   dnsNames,
			ACME: &v1alpha1.ACMECertificateConfig{
				Config: configs,
			},
		},
	}
}

func newSecret(name, namespace string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
	}
}
func TestSolverFor(t *testing.T) {
	type testT struct {
		*solverFixture
		domain             string
		expectErr          bool
		expectedSolverType reflect.Type
	}
	tests := map[string]testT{
		"loads secret for cloudflare provider": {
			solverFixture: &solverFixture{
				Builder: &test.Builder{
					KubeObjects: []runtime.Object{
						newSecret("cloudflare-key", "default", map[string][]byte{
							"api-key": []byte("a-cloudflare-api-key"),
						}),
					},
				},
				Issuer: newIssuer("test", "default", []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name: "fake-cloudflare",
						Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
							Email: "test",
							APIKey: v1alpha1.SecretKeySelector{
								LocalObjectReference: v1alpha1.LocalObjectReference{
									Name: "cloudflare-key",
								},
								Key: "api-key",
							},
						},
					},
				}),
				Challenge: v1alpha1.ACMEOrderChallenge{
					SolverConfig: v1alpha1.SolverConfig{
						DNS01: &v1alpha1.DNS01SolverConfig{
							Provider: "fake-cloudflare",
						},
					},
				},
			},
			domain:             "example.com",
			expectedSolverType: reflect.TypeOf(&cloudflare.DNSProvider{}),
		},
		"fails to load a cloudflare provider with a missing secret": {
			solverFixture: &solverFixture{
				Issuer: newIssuer("test", "default", []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name: "fake-cloudflare",
						Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
							Email: "test",
							APIKey: v1alpha1.SecretKeySelector{
								LocalObjectReference: v1alpha1.LocalObjectReference{
									Name: "cloudflare-key",
								},
								Key: "api-key",
							},
						},
					},
				}),
				// don't include any secrets in the lister
				Challenge: v1alpha1.ACMEOrderChallenge{
					SolverConfig: v1alpha1.SolverConfig{
						DNS01: &v1alpha1.DNS01SolverConfig{
							Provider: "fake-cloudflare",
						},
					},
				},
			},
			domain:    "example.com",
			expectErr: true,
		},
		"fails to load a cloudflare provider with an invalid secret": {
			solverFixture: &solverFixture{
				Builder: &test.Builder{
					KubeObjects: []runtime.Object{
						newSecret("cloudflare-key", "default", map[string][]byte{
							"api-key-oops": []byte("a-cloudflare-api-key"),
						}),
					},
				},
				Issuer: newIssuer("test", "default", []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name: "fake-cloudflare",
						Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
							Email: "test",
							APIKey: v1alpha1.SecretKeySelector{
								LocalObjectReference: v1alpha1.LocalObjectReference{
									Name: "cloudflare-key",
								},
								Key: "api-key",
							},
						},
					},
				}),
				Challenge: v1alpha1.ACMEOrderChallenge{
					SolverConfig: v1alpha1.SolverConfig{
						DNS01: &v1alpha1.DNS01SolverConfig{
							Provider: "fake-cloudflare",
						},
					},
				},
			},
			domain:    "example.com",
			expectErr: true,
		},
		"fails to load a provider with a non-existent provider set for the domain": {
			solverFixture: &solverFixture{
				Builder: &test.Builder{
					KubeObjects: []runtime.Object{
						newSecret("cloudflare-key", "default", map[string][]byte{
							"api-key": []byte("a-cloudflare-api-key"),
						}),
					},
				},
				Issuer: newIssuer("test", "default", []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name: "fake-cloudflare",
						Cloudflare: &v1alpha1.ACMEIssuerDNS01ProviderCloudflare{
							Email: "test",
							APIKey: v1alpha1.SecretKeySelector{
								LocalObjectReference: v1alpha1.LocalObjectReference{
									Name: "cloudflare-key",
								},
								Key: "api-key",
							},
						},
					},
				}),
				Challenge: v1alpha1.ACMEOrderChallenge{
					SolverConfig: v1alpha1.SolverConfig{
						DNS01: &v1alpha1.DNS01SolverConfig{
							Provider: "fake-cloudflare-oops",
						},
					},
				},
			},
			domain:    "example.com",
			expectErr: true,
		},
	}
	testFn := func(test testT) func(*testing.T) {
		return func(t *testing.T) {
			test.Setup(t)
			defer test.Finish(t)
			s := test.Solver
			dnsSolver, err := s.solverForIssuerProvider(test.Issuer, test.Challenge.SolverConfig.DNS01.Provider)
			if err != nil && !test.expectErr {
				t.Errorf("expected solverFor to not error, but got: %s", err.Error())
				return
			}
			typeOfSolver := reflect.TypeOf(dnsSolver)
			if typeOfSolver != test.expectedSolverType {
				t.Errorf("expected solver of type %q but got one of type %q", test.expectedSolverType, typeOfSolver)
				return
			}
		}
	}
	for name, test := range tests {
		t.Run(name, testFn(test))
	}
}

func TestRoute53TrimCreds(t *testing.T) {
	f := &solverFixture{
		Builder: &test.Builder{
			KubeObjects: []runtime.Object{
				newSecret("route53", "default", map[string][]byte{
					"secret": []byte("AKIENDINNEWLINE \n"),
				}),
			},
		},
		Issuer: newIssuer("test", "default", []v1alpha1.ACMEIssuerDNS01Provider{
			{
				Name: "fake-route53",
				Route53: &v1alpha1.ACMEIssuerDNS01ProviderRoute53{
					AccessKeyID: "  test_with_spaces  ",
					Region:      "us-west-2",
					SecretAccessKey: v1alpha1.SecretKeySelector{
						LocalObjectReference: v1alpha1.LocalObjectReference{
							Name: "route53",
						},
						Key: "secret",
					},
				},
			},
		}),
		Challenge: v1alpha1.ACMEOrderChallenge{
			SolverConfig: v1alpha1.SolverConfig{
				DNS01: &v1alpha1.DNS01SolverConfig{
					Provider: "fake-route53",
				},
			},
		},
		dnsProviders: newFakeDNSProviders(),
	}

	f.Setup(t)
	defer f.Finish(t)

	s := f.Solver
	_, err := s.solverForIssuerProvider(f.Issuer, f.Challenge.SolverConfig.DNS01.Provider)
	if err != nil {
		t.Fatalf("expected solverFor to not error, but got: %s", err)
	}

	expectedR53Call := []fakeDNSProviderCall{
		{
			name: "route53",
			args: []interface{}{"test_with_spaces", "AKIENDINNEWLINE", "", "us-west-2", false},
		},
	}

	if !reflect.DeepEqual(expectedR53Call, f.dnsProviders.calls) {
		t.Fatalf("expected %+v == %+v", expectedR53Call, f.dnsProviders.calls)
	}
}

func TestRoute53AmbientCreds(t *testing.T) {
	type result struct {
		expectedCall *fakeDNSProviderCall
		expectedErr  error
	}

	tests := []struct {
		in  solverFixture
		out result
	}{
		{
			solverFixture{
				Builder: &test.Builder{
					Context: &controller.Context{
						IssuerOptions: controller.IssuerOptions{
							IssuerAmbientCredentials: true,
						},
					},
				},
				Issuer: newIssuer("test", "default", []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name: "fake-route53",
						Route53: &v1alpha1.ACMEIssuerDNS01ProviderRoute53{
							Region: "us-west-2",
						},
					},
				}),
				dnsProviders: newFakeDNSProviders(),
				Challenge: v1alpha1.ACMEOrderChallenge{
					SolverConfig: v1alpha1.SolverConfig{
						DNS01: &v1alpha1.DNS01SolverConfig{
							Provider: "fake-route53",
						},
					},
				},
			},
			result{
				expectedCall: &fakeDNSProviderCall{
					name: "route53",
					args: []interface{}{"", "", "", "us-west-2", true},
				},
			},
		},
		{
			solverFixture{
				Builder: &test.Builder{
					Context: &controller.Context{
						IssuerOptions: controller.IssuerOptions{
							IssuerAmbientCredentials: false,
						},
					},
				},
				Issuer: newIssuer("test", "default", []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name: "fake-route53",
						Route53: &v1alpha1.ACMEIssuerDNS01ProviderRoute53{
							Region: "us-west-2",
						},
					},
				}),
				dnsProviders: newFakeDNSProviders(),
				Challenge: v1alpha1.ACMEOrderChallenge{
					SolverConfig: v1alpha1.SolverConfig{
						DNS01: &v1alpha1.DNS01SolverConfig{
							Provider: "fake-route53",
						},
					},
				},
			},
			result{
				expectedCall: &fakeDNSProviderCall{
					name: "route53",
					args: []interface{}{"", "", "", "us-west-2", false},
				},
			},
		},
	}

	for _, tt := range tests {
		f := tt.in
		f.Setup(t)
		defer f.Finish(t)
		s := f.Solver
		_, err := s.solverForIssuerProvider(f.Issuer, f.Challenge.SolverConfig.DNS01.Provider)
		if !reflect.DeepEqual(tt.out.expectedErr, err) {
			t.Fatalf("expected error %v, got error %v", tt.out.expectedErr, err)
		}

		if tt.out.expectedCall != nil {
			if !reflect.DeepEqual([]fakeDNSProviderCall{*tt.out.expectedCall}, f.dnsProviders.calls) {
				t.Fatalf("expected %+v == %+v", []fakeDNSProviderCall{*tt.out.expectedCall}, f.dnsProviders.calls)
			}
		}
	}
}
