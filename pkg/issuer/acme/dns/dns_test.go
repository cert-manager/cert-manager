package dns

import (
	"errors"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubeinformers "k8s.io/client-go/informers"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/azuredns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/clouddns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/cloudflare"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/route53"
)

type fixture struct {
	// Issuer resource this solver is for
	Issuer v1alpha1.GenericIssuer

	// Objects here are pre-loaded into the fake client
	KubeObjects []runtime.Object

	// Secret objects to store in the fake lister
	SecretLister []*corev1.Secret

	// the resourceNamespace to set on the solver
	ResourceNamespace string

	// certificate used in the test
	Certificate *v1alpha1.Certificate

	Challenge v1alpha1.ACMEOrderChallenge

	DNSProviders *fakeDNSProviders

	Ambient bool
}

type fakeDNSProviderCall struct {
	name string
	args []interface{}
}

type fakeDNSProviders struct {
	constructors dnsProviderConstructors
	calls        []fakeDNSProviderCall
}

func (f *fakeDNSProviders) call(name string, args ...interface{}) {
	f.calls = append(f.calls, fakeDNSProviderCall{name: name, args: args})
}

func newFakeDNSProviders() *fakeDNSProviders {
	f := &fakeDNSProviders{
		calls: []fakeDNSProviderCall{},
	}
	f.constructors = dnsProviderConstructors{
		cloudDNS: func(project string, serviceAccount []byte) (*clouddns.DNSProvider, error) {
			f.call("clouddns", project, serviceAccount)
			return nil, nil
		},
		cloudFlare: func(email, apikey string) (*cloudflare.DNSProvider, error) {
			f.call("cloudflare", email, apikey)
			if email == "" || apikey == "" {
				return nil, errors.New("invalid email or apikey")
			}
			return nil, nil
		},
		route53: func(accessKey, secretKey, hostedZoneID, region string, ambient bool) (*route53.DNSProvider, error) {
			f.call("route53", accessKey, secretKey, hostedZoneID, region, ambient)
			return nil, nil
		},
		azureDNS: func(clientID, clientSecret, subscriptionID, tenentID, resourceGroupName, hostedZoneName string) (*azuredns.DNSProvider, error) {
			f.call("azuredns", clientID, clientSecret, subscriptionID, tenentID, resourceGroupName, hostedZoneName)
			return nil, nil
		},
	}
	return f
}

func (f *fixture) solver() *Solver {
	kubeClient := kubefake.NewSimpleClientset(f.KubeObjects...)
	sharedInformerFactory := kubeinformers.NewSharedInformerFactory(kubeClient, 0)
	secretsLister := sharedInformerFactory.Core().V1().Secrets().Lister()
	for _, s := range f.SecretLister {
		sharedInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(s)
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	sharedInformerFactory.Start(stopCh)
	dnsProvider := f.DNSProviders
	if dnsProvider == nil {
		dnsProvider = newFakeDNSProviders()
	}
	return &Solver{
		f.Issuer,
		kubeClient,
		secretsLister,
		f.ResourceNamespace,
		dnsProvider.constructors,
		f.Ambient,
		[]string{"8.8.8.8:53"},
	}
}

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
		f                  *fixture
		domain             string
		expectErr          bool
		expectedSolverType reflect.Type
	}
	tests := map[string]testT{
		"loads secret for cloudflare provider": {
			f: &fixture{
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
				SecretLister: []*corev1.Secret{newSecret("cloudflare-key", "default", map[string][]byte{
					"api-key": []byte("a-cloudflare-api-key"),
				})},
				ResourceNamespace: "default",
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
			f: &fixture{
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
				SecretLister:      []*corev1.Secret{},
				ResourceNamespace: "default",
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
			f: &fixture{
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
				SecretLister: []*corev1.Secret{newSecret("cloudflare-key", "default", map[string][]byte{
					"api-key-oops": []byte("a-cloudflare-api-key"),
				})},
				ResourceNamespace: "default",
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
			f: &fixture{
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
				SecretLister: []*corev1.Secret{newSecret("cloudflare-key", "default", map[string][]byte{
					"api-key": []byte("a-cloudflare-api-key"),
				})},
				ResourceNamespace: "default",
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
			s := test.f.solver()
			dnsSolver, err := s.solverForIssuerProvider(test.f.Challenge.SolverConfig.DNS01.Provider)
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
	f := &fixture{
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
		SecretLister: []*corev1.Secret{newSecret("route53", "default", map[string][]byte{
			"secret": []byte("AKIENDINNEWLINE \n"),
		})},
		ResourceNamespace: "default",
		Challenge: v1alpha1.ACMEOrderChallenge{
			SolverConfig: v1alpha1.SolverConfig{
				DNS01: &v1alpha1.DNS01SolverConfig{
					Provider: "fake-route53",
				},
			},
		},
		DNSProviders: newFakeDNSProviders(),
	}

	s := f.solver()
	_, err := s.solverForIssuerProvider(f.Challenge.SolverConfig.DNS01.Provider)
	if err != nil {
		t.Fatalf("expected solverFor to not error, but got: %s", err)
	}

	expectedR53Call := []fakeDNSProviderCall{
		{
			name: "route53",
			args: []interface{}{"test_with_spaces", "AKIENDINNEWLINE", "", "us-west-2", false},
		},
	}

	if !reflect.DeepEqual(expectedR53Call, f.DNSProviders.calls) {
		t.Fatalf("expected %+v == %+v", expectedR53Call, f.DNSProviders.calls)
	}
}

func TestRoute53AmbientCreds(t *testing.T) {
	type result struct {
		expectedCall *fakeDNSProviderCall
		expectedErr  error
	}

	tests := []struct {
		in  fixture
		out result
	}{
		{
			fixture{
				Issuer: newIssuer("test", "default", []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name: "fake-route53",
						Route53: &v1alpha1.ACMEIssuerDNS01ProviderRoute53{
							Region: "us-west-2",
						},
					},
				}),
				DNSProviders: newFakeDNSProviders(),
				Challenge: v1alpha1.ACMEOrderChallenge{
					SolverConfig: v1alpha1.SolverConfig{
						DNS01: &v1alpha1.DNS01SolverConfig{
							Provider: "fake-route53",
						},
					},
				},
				Ambient: true,
			},
			result{
				expectedCall: &fakeDNSProviderCall{
					name: "route53",
					args: []interface{}{"", "", "", "us-west-2", true},
				},
			},
		},
		{
			fixture{
				Issuer: newIssuer("test", "default", []v1alpha1.ACMEIssuerDNS01Provider{
					{
						Name: "fake-route53",
						Route53: &v1alpha1.ACMEIssuerDNS01ProviderRoute53{
							Region: "us-west-2",
						},
					},
				}),
				DNSProviders: newFakeDNSProviders(),
				Challenge: v1alpha1.ACMEOrderChallenge{
					SolverConfig: v1alpha1.SolverConfig{
						DNS01: &v1alpha1.DNS01SolverConfig{
							Provider: "fake-route53",
						},
					},
				},
				Ambient: false,
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
		s := f.solver()
		_, err := s.solverForIssuerProvider(f.Challenge.SolverConfig.DNS01.Provider)
		if !reflect.DeepEqual(tt.out.expectedErr, err) {
			t.Fatalf("expected error %v, got error %v", tt.out.expectedErr, err)
		}

		if tt.out.expectedCall != nil {
			if !reflect.DeepEqual([]fakeDNSProviderCall{*tt.out.expectedCall}, f.DNSProviders.calls) {
				t.Fatalf("expected %+v == %+v", []fakeDNSProviderCall{*tt.out.expectedCall}, f.DNSProviders.calls)
			}
		}
	}
}
