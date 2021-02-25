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

package dns

import (
	"context"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/acmedns"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/cloudflare"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

func newIssuer(name, namespace string) *v1.Issuer {
	return &v1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.IssuerSpec{
			IssuerConfig: v1.IssuerConfig{
				ACME: &cmacme.ACMEIssuer{},
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
		"loads api key for cloudflare provider": {
			solverFixture: &solverFixture{
				Builder: &test.Builder{
					KubeObjects: []runtime.Object{
						newSecret("cloudflare-key", "default", map[string][]byte{
							"api-key": []byte("a-cloudflare-api-key"),
						}),
					},
				},
				Issuer: newIssuer("test", "default"),
				Challenge: &cmacme.Challenge{
					Spec: cmacme.ChallengeSpec{
						Solver: cmacme.ACMEChallengeSolver{
							DNS01: &cmacme.ACMEChallengeSolverDNS01{
								Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
									Email: "test",
									APIKey: &cmmeta.SecretKeySelector{
										LocalObjectReference: cmmeta.LocalObjectReference{
											Name: "cloudflare-key",
										},
										Key: "api-key",
									},
								},
							},
						},
					},
				},
			},
			domain:             "example.com",
			expectedSolverType: reflect.TypeOf(&cloudflare.DNSProvider{}),
		},
		"loads api token for cloudflare provider": {
			solverFixture: &solverFixture{
				Builder: &test.Builder{
					KubeObjects: []runtime.Object{
						newSecret("cloudflare-token", "default", map[string][]byte{
							"api-token": []byte("a-cloudflare-api-token"),
						}),
					},
				},
				Issuer: newIssuer("test", "default"),
				Challenge: &cmacme.Challenge{
					Spec: cmacme.ChallengeSpec{
						Solver: cmacme.ACMEChallengeSolver{
							DNS01: &cmacme.ACMEChallengeSolverDNS01{
								Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
									Email: "test",
									APIToken: &cmmeta.SecretKeySelector{
										LocalObjectReference: cmmeta.LocalObjectReference{
											Name: "cloudflare-token",
										},
										Key: "api-token",
									},
								},
							},
						},
					},
				},
			},
			domain:             "example.com",
			expectedSolverType: reflect.TypeOf(&cloudflare.DNSProvider{}),
		},
		"fails to load a cloudflare provider with a missing secret": {
			solverFixture: &solverFixture{
				Issuer: newIssuer("test", "default"),
				// don't include any secrets in the lister
				Challenge: &cmacme.Challenge{
					Spec: cmacme.ChallengeSpec{
						Solver: cmacme.ACMEChallengeSolver{
							DNS01: &cmacme.ACMEChallengeSolverDNS01{
								Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
									Email: "test",
									APIToken: &cmmeta.SecretKeySelector{
										LocalObjectReference: cmmeta.LocalObjectReference{
											Name: "cloudflare-token",
										},
										Key: "api-token",
									},
								},
							},
						},
					},
				},
			},
			domain:    "example.com",
			expectErr: true,
		},
		"fails to load a cloudflare provider when key and token are provided": {
			solverFixture: &solverFixture{
				Issuer: newIssuer("test", "default"),
				// don't include any secrets in the lister
				Challenge: &cmacme.Challenge{
					Spec: cmacme.ChallengeSpec{
						Solver: cmacme.ACMEChallengeSolver{
							DNS01: &cmacme.ACMEChallengeSolverDNS01{
								Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
									Email: "test",
									APIToken: &cmmeta.SecretKeySelector{
										LocalObjectReference: cmmeta.LocalObjectReference{
											Name: "cloudflare-token",
										},
										Key: "api-token",
									},
									APIKey: &cmmeta.SecretKeySelector{
										LocalObjectReference: cmmeta.LocalObjectReference{
											Name: "cloudflare-key",
										},
										Key: "api-key",
									},
								},
							},
						},
					},
				},
			},
			domain:    "example.com",
			expectErr: true,
		},
		"fails to load a cloudflare provider with an invalid key secret": {
			solverFixture: &solverFixture{
				Builder: &test.Builder{
					KubeObjects: []runtime.Object{
						newSecret("cloudflare-key", "default", map[string][]byte{
							"api-key-oops": []byte("a-cloudflare-api-key"),
						}),
					},
				},
				Issuer: newIssuer("test", "default"),
				Challenge: &cmacme.Challenge{
					Spec: cmacme.ChallengeSpec{
						Solver: cmacme.ACMEChallengeSolver{
							DNS01: &cmacme.ACMEChallengeSolverDNS01{
								Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
									Email: "test",
									APIKey: &cmmeta.SecretKeySelector{
										LocalObjectReference: cmmeta.LocalObjectReference{
											Name: "cloudflare-key",
										},
										Key: "api-key",
									},
								},
							},
						},
					},
				},
			},
			domain:    "example.com",
			expectErr: true,
		},
		"fails to load a cloudflare provider with an invalid token secret": {
			solverFixture: &solverFixture{
				Builder: &test.Builder{
					KubeObjects: []runtime.Object{
						newSecret("cloudflare-token", "default", map[string][]byte{
							"api-key-oops": []byte("a-cloudflare-api-token"),
						}),
					},
				},
				Issuer: newIssuer("test", "default"),
				Challenge: &cmacme.Challenge{
					Spec: cmacme.ChallengeSpec{
						Solver: cmacme.ACMEChallengeSolver{
							DNS01: &cmacme.ACMEChallengeSolverDNS01{
								Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
									Email: "test",
									APIToken: &cmmeta.SecretKeySelector{
										LocalObjectReference: cmmeta.LocalObjectReference{
											Name: "cloudflare-token",
										},
										Key: "api-token",
									},
								},
							},
						},
					},
				},
			},
			domain:    "example.com",
			expectErr: true,
		},
		"loads json for acmedns provider": {
			solverFixture: &solverFixture{
				Builder: &test.Builder{
					KubeObjects: []runtime.Object{
						newSecret("acmedns-key", "default", map[string][]byte{
							"acmedns.json": []byte("{}"),
						}),
					},
				},
				Issuer: newIssuer("test", "default"),
				Challenge: &cmacme.Challenge{
					Spec: cmacme.ChallengeSpec{
						Solver: cmacme.ACMEChallengeSolver{
							DNS01: &cmacme.ACMEChallengeSolverDNS01{
								AcmeDNS: &cmacme.ACMEIssuerDNS01ProviderAcmeDNS{
									Host: "http://127.0.0.1/",
									AccountSecret: cmmeta.SecretKeySelector{
										LocalObjectReference: cmmeta.LocalObjectReference{
											Name: "acmedns-key",
										},
										Key: "acmedns.json",
									},
								},
							},
						},
					},
				},
			},
			domain:             "example.com",
			expectedSolverType: reflect.TypeOf(&acmedns.DNSProvider{}),
		},
	}
	testFn := func(test testT) func(*testing.T) {
		return func(t *testing.T) {
			test.Setup(t)
			defer test.Finish(t)
			s := test.Solver
			dnsSolver, _, err := s.solverForChallenge(context.Background(), test.Issuer, test.Challenge)
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

func TestSolveForDigitalOcean(t *testing.T) {
	f := &solverFixture{
		Builder: &test.Builder{
			KubeObjects: []runtime.Object{
				newSecret("digitalocean", "default", map[string][]byte{
					"token": []byte("FAKE-TOKEN"),
				}),
			},
		},
		Issuer: newIssuer("test", "default"),
		Challenge: &cmacme.Challenge{
			Spec: cmacme.ChallengeSpec{
				Solver: cmacme.ACMEChallengeSolver{
					DNS01: &cmacme.ACMEChallengeSolverDNS01{
						DigitalOcean: &cmacme.ACMEIssuerDNS01ProviderDigitalOcean{
							Token: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "digitalocean",
								},
								Key: "token",
							},
						},
					},
				},
			},
		},
		dnsProviders: newFakeDNSProviders(),
	}

	f.Setup(t)
	defer f.Finish(t)

	s := f.Solver
	_, _, err := s.solverForChallenge(context.Background(), f.Issuer, f.Challenge)
	if err != nil {
		t.Fatalf("expected solverFor to not error, but got: %s", err)
	}

	expectedDOCall := []fakeDNSProviderCall{
		{
			name: "digitalocean",
			args: []interface{}{"FAKE-TOKEN", util.RecursiveNameservers},
		},
	}

	if !reflect.DeepEqual(expectedDOCall, f.dnsProviders.calls) {
		t.Fatalf("expected %+v == %+v", expectedDOCall, f.dnsProviders.calls)
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
		Issuer: newIssuer("test", "default"),
		Challenge: &cmacme.Challenge{
			Spec: cmacme.ChallengeSpec{
				Solver: cmacme.ACMEChallengeSolver{
					DNS01: &cmacme.ACMEChallengeSolverDNS01{
						Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
							AccessKeyID: "  test_with_spaces  ",
							Region:      "us-west-2",
							SecretAccessKey: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "route53",
								},
								Key: "secret",
							},
						},
					},
				},
			},
		},
		dnsProviders: newFakeDNSProviders(),
	}

	f.Setup(t)
	defer f.Finish(t)

	s := f.Solver
	_, _, err := s.solverForChallenge(context.Background(), f.Issuer, f.Challenge)
	if err != nil {
		t.Fatalf("expected solverFor to not error, but got: %s", err)
	}

	expectedR53Call := []fakeDNSProviderCall{
		{
			name: "route53",
			args: []interface{}{"test_with_spaces", "AKIENDINNEWLINE", "", "us-west-2", "", false, util.RecursiveNameservers},
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
				Issuer:       newIssuer("test", "default"),
				dnsProviders: newFakeDNSProviders(),
				Challenge: &cmacme.Challenge{
					Spec: cmacme.ChallengeSpec{
						Solver: cmacme.ACMEChallengeSolver{
							DNS01: &cmacme.ACMEChallengeSolverDNS01{
								Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
									Region: "us-west-2",
								},
							},
						},
					},
				},
			},
			result{
				expectedCall: &fakeDNSProviderCall{
					name: "route53",
					args: []interface{}{"", "", "", "us-west-2", "", true, util.RecursiveNameservers},
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
				Issuer:       newIssuer("test", "default"),
				dnsProviders: newFakeDNSProviders(),
				Challenge: &cmacme.Challenge{
					Spec: cmacme.ChallengeSpec{
						Solver: cmacme.ACMEChallengeSolver{
							DNS01: &cmacme.ACMEChallengeSolverDNS01{
								Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
									Region: "us-west-2",
								},
							},
						},
					},
				},
			},
			result{
				expectedCall: &fakeDNSProviderCall{
					name: "route53",
					args: []interface{}{"", "", "", "us-west-2", "", false, util.RecursiveNameservers},
				},
			},
		},
	}

	for _, tt := range tests {
		f := tt.in
		f.Setup(t)
		defer f.Finish(t)
		s := f.Solver
		_, _, err := s.solverForChallenge(context.Background(), f.Issuer, f.Challenge)
		if tt.out.expectedErr != err {
			t.Fatalf("expected error %v, got error %v", tt.out.expectedErr, err)
		}

		if tt.out.expectedCall != nil {
			if !reflect.DeepEqual([]fakeDNSProviderCall{*tt.out.expectedCall}, f.dnsProviders.calls) {
				t.Fatalf("expected %+v == %+v", []fakeDNSProviderCall{*tt.out.expectedCall}, f.dnsProviders.calls)
			}
		}
	}
}

func TestRoute53AssumeRole(t *testing.T) {
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
				Issuer:       newIssuer("test", "default"),
				dnsProviders: newFakeDNSProviders(),
				Challenge: &cmacme.Challenge{
					Spec: cmacme.ChallengeSpec{
						Solver: cmacme.ACMEChallengeSolver{
							DNS01: &cmacme.ACMEChallengeSolverDNS01{
								Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
									Region: "us-west-2",
									Role:   "my-role",
								},
							},
						},
					},
				},
			},
			result{
				expectedCall: &fakeDNSProviderCall{
					name: "route53",
					args: []interface{}{"", "", "", "us-west-2", "my-role", true, util.RecursiveNameservers},
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
				Issuer:       newIssuer("test", "default"),
				dnsProviders: newFakeDNSProviders(),
				Challenge: &cmacme.Challenge{
					Spec: cmacme.ChallengeSpec{
						Solver: cmacme.ACMEChallengeSolver{
							DNS01: &cmacme.ACMEChallengeSolverDNS01{
								Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
									Region: "us-west-2",
									Role:   "my-other-role",
								},
							},
						},
					},
				},
			},
			result{
				expectedCall: &fakeDNSProviderCall{
					name: "route53",
					args: []interface{}{"", "", "", "us-west-2", "my-other-role", false, util.RecursiveNameservers},
				},
			},
		},
	}

	for _, tt := range tests {
		f := tt.in
		f.Setup(t)
		defer f.Finish(t)
		s := f.Solver
		_, _, err := s.solverForChallenge(context.Background(), f.Issuer, f.Challenge)
		if tt.out.expectedErr != err {
			t.Fatalf("expected error %v, got error %v", tt.out.expectedErr, err)
		}

		if tt.out.expectedCall != nil {
			if !reflect.DeepEqual([]fakeDNSProviderCall{*tt.out.expectedCall}, f.dnsProviders.calls) {
				t.Fatalf("expected %+v == %+v", []fakeDNSProviderCall{*tt.out.expectedCall}, f.dnsProviders.calls)
			}
		}
	}
}
