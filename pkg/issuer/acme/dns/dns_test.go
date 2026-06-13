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
	"net/http"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/acmedns"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/cloudflare"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

const (
	fakeIssuerNamespace                = "fake-issuer-namespace"
	fakeClusterIssuerResourceNamespace = "fake-cluster-resource-namespace"
)

func newSecret(name string, data map[string][]byte, namespace string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
	}
}

func TestClusterIssuerNamespace(t *testing.T) {
	f := &solverFixture{
		Builder: &test.Builder{
			KubeObjects: []runtime.Object{
				newSecret(
					"route53",
					map[string][]byte{
						"secret": []byte("AKIENDINNEWLINE \n"),
					},
					fakeClusterIssuerResourceNamespace, // since this is a ClusterIssuer, the secret should be in the clusterResourceNamespace
				),
			},
			Context: &controller.Context{
				ContextOptions: controller.ContextOptions{
					IssuerOptions: controller.IssuerOptions{
						ClusterResourceNamespace: fakeClusterIssuerResourceNamespace,
					},
				},
			},
		},
		Challenge: &cmacme.Challenge{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "random-certificate-namespace", // Random namespace in which the Certificate and Challenge live
			},
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
				IssuerRef: cmmeta.IssuerReference{
					Name: "test-issuer",
					Kind: "ClusterIssuer", // ClusterIssuer reference, so should use the clusterResourceNamespace
				},
			},
		},
		dnsProviders: newFakeDNSProviders(),
	}

	f.Setup(t)
	defer f.Finish(t)

	s := f.Solver
	_, _, err := s.solverForChallenge(t.Context(), f.Challenge)
	if err != nil {
		t.Fatalf("expected solverFor to not error, but got: %s", err)
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
						newSecret("cloudflare-key", map[string][]byte{
							"api-key": []byte("a-cloudflare-api-key"),
						}, fakeIssuerNamespace),
					},
				},
				Challenge: &cmacme.Challenge{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: fakeIssuerNamespace,
					},
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
						IssuerRef: cmmeta.IssuerReference{
							Name: "test-issuer",
						},
					},
				},
			},
			domain:             "example.com",
			expectedSolverType: reflect.TypeFor[*cloudflare.DNSProvider](),
		},
		"loads api token for cloudflare provider": {
			solverFixture: &solverFixture{
				Builder: &test.Builder{
					KubeObjects: []runtime.Object{
						newSecret("cloudflare-token", map[string][]byte{
							"api-token": []byte("a-cloudflare-api-token"),
						}, fakeIssuerNamespace),
					},
				},
				Challenge: &cmacme.Challenge{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: fakeIssuerNamespace,
					},
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
						IssuerRef: cmmeta.IssuerReference{
							Name: "test-issuer",
						},
					},
				},
			},
			domain:             "example.com",
			expectedSolverType: reflect.TypeFor[*cloudflare.DNSProvider](),
		},
		"fails to load a cloudflare provider with a missing secret": {
			solverFixture: &solverFixture{
				// don't include any secrets in the lister
				Challenge: &cmacme.Challenge{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: fakeIssuerNamespace,
					},
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
						IssuerRef: cmmeta.IssuerReference{
							Name: "test-issuer",
						},
					},
				},
			},
			domain:    "example.com",
			expectErr: true,
		},
		"fails to load a cloudflare provider when key and token are provided": {
			solverFixture: &solverFixture{
				// don't include any secrets in the lister
				Challenge: &cmacme.Challenge{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: fakeIssuerNamespace,
					},
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
						IssuerRef: cmmeta.IssuerReference{
							Name: "test-issuer",
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
						newSecret("cloudflare-key", map[string][]byte{
							"api-key-oops": []byte("a-cloudflare-api-key"),
						}, fakeIssuerNamespace),
					},
				},
				Challenge: &cmacme.Challenge{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: fakeIssuerNamespace,
					},
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
						IssuerRef: cmmeta.IssuerReference{
							Name: "test-issuer",
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
						newSecret("cloudflare-token", map[string][]byte{
							"api-key-oops": []byte("a-cloudflare-api-token"),
						}, fakeIssuerNamespace),
					},
				},
				Challenge: &cmacme.Challenge{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: fakeIssuerNamespace,
					},
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
						IssuerRef: cmmeta.IssuerReference{
							Name: "test-issuer",
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
						newSecret("acmedns-key", map[string][]byte{
							"acmedns.json": []byte("{}"),
						}, fakeIssuerNamespace),
					},
				},
				Challenge: &cmacme.Challenge{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: fakeIssuerNamespace,
					},
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
						IssuerRef: cmmeta.IssuerReference{
							Name: "test-issuer",
						},
					},
				},
			},
			domain:             "example.com",
			expectedSolverType: reflect.TypeFor[*acmedns.DNSProvider](),
		},
	}
	testFn := func(test testT) func(*testing.T) {
		return func(t *testing.T) {
			test.Setup(t)
			defer test.Finish(t)
			s := test.Solver
			dnsSolver, _, err := s.solverForChallenge(t.Context(), test.Challenge)
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
				newSecret("digitalocean", map[string][]byte{
					"token": []byte("FAKE-TOKEN"),
				}, fakeIssuerNamespace),
			},
		},
		Challenge: &cmacme.Challenge{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: fakeIssuerNamespace,
			},
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
				IssuerRef: cmmeta.IssuerReference{
					Name: "test-issuer",
				},
			},
		},
		dnsProviders: newFakeDNSProviders(),
	}

	f.Setup(t)
	defer f.Finish(t)

	s := f.Solver
	_, _, err := s.solverForChallenge(t.Context(), f.Challenge)
	if err != nil {
		t.Fatalf("expected solverFor to not error, but got: %s", err)
	}

	expectedDOCall := []fakeDNSProviderCall{
		{
			name: "digitalocean",
			args: []any{"FAKE-TOKEN", util.RecursiveNameservers},
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
				newSecret("route53", map[string][]byte{
					"secret": []byte("AKIENDINNEWLINE \n"),
				}, fakeIssuerNamespace),
			},
		},
		Challenge: &cmacme.Challenge{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: fakeIssuerNamespace,
			},
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
				IssuerRef: cmmeta.IssuerReference{
					Name: "test-issuer",
				},
			},
		},
		dnsProviders: newFakeDNSProviders(),
	}

	f.Setup(t)
	defer f.Finish(t)

	s := f.Solver
	_, _, err := s.solverForChallenge(t.Context(), f.Challenge)
	if err != nil {
		t.Fatalf("expected solverFor to not error, but got: %s", err)
	}

	expectedR53Call := []fakeDNSProviderCall{
		{
			name: "route53",
			args: []any{"test_with_spaces", "AKIENDINNEWLINE", "", "us-west-2", "", "", false, util.RecursiveNameservers},
		},
	}

	if !reflect.DeepEqual(expectedR53Call, f.dnsProviders.calls) {
		t.Fatalf("expected %+v == %+v", expectedR53Call, f.dnsProviders.calls)
	}
}

func TestRoute53SecretAccessKey(t *testing.T) {
	f := &solverFixture{
		Builder: &test.Builder{
			KubeObjects: []runtime.Object{
				newSecret("route53", map[string][]byte{
					"accessKeyID":     []byte("AWSACCESSKEYID"),
					"secretAccessKey": []byte("AKIENDINNEWLINE \n"),
				}, fakeIssuerNamespace),
			},
		},
		Challenge: &cmacme.Challenge{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: fakeIssuerNamespace,
			},
			Spec: cmacme.ChallengeSpec{
				Solver: cmacme.ACMEChallengeSolver{
					DNS01: &cmacme.ACMEChallengeSolverDNS01{
						Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
							SecretAccessKeyID: &cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "route53",
								},
								Key: "accessKeyID",
							},
							Region: "us-west-2",
							SecretAccessKey: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "route53",
								},
								Key: "secretAccessKey",
							},
						},
					},
				},
				IssuerRef: cmmeta.IssuerReference{
					Name: "test-issuer",
				},
			},
		},
		dnsProviders: newFakeDNSProviders(),
	}

	f.Setup(t)
	defer f.Finish(t)

	s := f.Solver
	_, _, err := s.solverForChallenge(t.Context(), f.Challenge)
	if err != nil {
		t.Fatalf("expected solverFor to not error, but got: %s", err)
	}

	expectedR53Call := []fakeDNSProviderCall{
		{
			name: "route53",
			args: []any{"AWSACCESSKEYID", "AKIENDINNEWLINE", "", "us-west-2", "", "", false, util.RecursiveNameservers},
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
						RESTConfig: new(rest.Config),
						ContextOptions: controller.ContextOptions{
							IssuerOptions: controller.IssuerOptions{
								IssuerAmbientCredentials: true,
							},
						},
					},
				},
				dnsProviders: newFakeDNSProviders(),
				Challenge: gen.Challenge("",
					gen.SetChallengeNamespace(fakeIssuerNamespace),
					gen.SetChallengeIssuer(cmmeta.IssuerReference{Name: "test-issuer"}),
					gen.SetChallengeSolverDNS01(cmacme.ACMEChallengeSolverDNS01{
						Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
							Region: "us-west-2",
						}}),
				),
			},
			result{
				expectedCall: &fakeDNSProviderCall{
					name: "route53",
					args: []any{"", "", "", "us-west-2", "", "", true, util.RecursiveNameservers},
				},
			},
		},
		{
			solverFixture{
				Builder: &test.Builder{
					Context: &controller.Context{
						RESTConfig: new(rest.Config),
						ContextOptions: controller.ContextOptions{
							IssuerOptions: controller.IssuerOptions{
								IssuerAmbientCredentials: false,
							},
						},
					},
				},
				dnsProviders: newFakeDNSProviders(),
				Challenge: &cmacme.Challenge{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: fakeIssuerNamespace,
					},
					Spec: cmacme.ChallengeSpec{
						Solver: cmacme.ACMEChallengeSolver{
							DNS01: &cmacme.ACMEChallengeSolverDNS01{
								Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
									Region: "us-west-2",
								},
							},
						},
						IssuerRef: cmmeta.IssuerReference{
							Name: "test-issuer",
						},
					},
				},
			},
			result{
				expectedCall: &fakeDNSProviderCall{
					name: "route53",
					args: []any{"", "", "", "us-west-2", "", "", false, util.RecursiveNameservers},
				},
			},
		},
	}

	for _, tt := range tests {
		f := tt.in
		f.Setup(t)
		defer f.Finish(t)
		s := f.Solver
		_, _, err := s.solverForChallenge(t.Context(), f.Challenge)
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
						RESTConfig: new(rest.Config),
						ContextOptions: controller.ContextOptions{
							IssuerOptions: controller.IssuerOptions{
								IssuerAmbientCredentials: true,
							},
						},
					},
				},
				dnsProviders: newFakeDNSProviders(),
				Challenge: gen.Challenge("",
					gen.SetChallengeNamespace(fakeIssuerNamespace),
					gen.SetChallengeIssuer(cmmeta.IssuerReference{Name: "test-issuer"}),
					gen.SetChallengeSolverDNS01(cmacme.ACMEChallengeSolverDNS01{
						Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
							Region: "us-west-2",
							Role:   "my-role",
						}}),
				),
			},
			result{
				expectedCall: &fakeDNSProviderCall{
					name: "route53",
					args: []any{"", "", "", "us-west-2", "my-role", "", true, util.RecursiveNameservers},
				},
			},
		},
		{
			solverFixture{
				Builder: &test.Builder{
					Context: &controller.Context{
						RESTConfig: new(rest.Config),
						ContextOptions: controller.ContextOptions{
							IssuerOptions: controller.IssuerOptions{
								IssuerAmbientCredentials: false,
							},
						},
					},
				},
				dnsProviders: newFakeDNSProviders(),
				Challenge: &cmacme.Challenge{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: fakeIssuerNamespace,
					},
					Spec: cmacme.ChallengeSpec{
						Solver: cmacme.ACMEChallengeSolver{
							DNS01: &cmacme.ACMEChallengeSolverDNS01{
								Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
									Region: "us-west-2",
									Role:   "my-other-role",
								},
							},
						},
						IssuerRef: cmmeta.IssuerReference{
							Name: "test-issuer",
						},
					},
				},
			},
			result{
				expectedCall: &fakeDNSProviderCall{
					name: "route53",
					args: []any{"", "", "", "us-west-2", "my-other-role", "", false, util.RecursiveNameservers},
				},
			},
		},
	}

	for _, tt := range tests {
		f := tt.in
		f.Setup(t)
		defer f.Finish(t)
		s := f.Solver
		_, _, err := s.solverForChallenge(t.Context(), f.Challenge)
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

func TestSolverForAcmeDNSPassesHTTPClient(t *testing.T) {
	validCAPEM := mustGenerateCAPEM(t)

	tests := map[string]struct {
		caBundle      []byte
		wantNilClient bool
	}{
		"per-solver caBundle produces non-nil httpClient passed to acmeDNS constructor": {
			caBundle:      validCAPEM,
			wantNilClient: false,
		},
		"no caBundle produces nil httpClient passed to acmeDNS constructor": {
			caBundle:      nil,
			wantNilClient: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := &solverFixture{
				Builder: &test.Builder{
					KubeObjects: []runtime.Object{
						newSecret("acmedns-key", map[string][]byte{
							"acmedns.json": []byte("{}"),
						}, fakeIssuerNamespace),
					},
				},
				Challenge: &cmacme.Challenge{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: fakeIssuerNamespace,
					},
					Spec: cmacme.ChallengeSpec{
						Solver: cmacme.ACMEChallengeSolver{
							DNS01: &cmacme.ACMEChallengeSolverDNS01{
								AcmeDNS: &cmacme.ACMEIssuerDNS01ProviderAcmeDNS{
									Host: "https://acme-dns.example.com",
									AccountSecret: cmmeta.SecretKeySelector{
										LocalObjectReference: cmmeta.LocalObjectReference{
											Name: "acmedns-key",
										},
										Key: "acmedns.json",
									},
									CABundle: tc.caBundle,
								},
							},
						},
						IssuerRef: cmmeta.IssuerReference{
							Name: "test-issuer",
						},
					},
				},
				dnsProviders: newFakeDNSProviders(),
			}

			f.Setup(t)
			defer f.Finish(t)

			_, _, err := f.Solver.solverForChallenge(t.Context(), f.Challenge)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}

			if len(f.dnsProviders.calls) != 1 {
				t.Fatalf("expected 1 provider call, got %d", len(f.dnsProviders.calls))
			}

			call := f.dnsProviders.calls[0]
			if call.name != "acmedns" {
				t.Fatalf("expected acmedns call, got %q", call.name)
			}

			if len(call.args) < 4 {
				t.Fatalf("expected at least 4 args in acmedns call, got %d", len(call.args))
			}

			httpClient, _ := call.args[3].(*http.Client)

			if tc.wantNilClient {
				if httpClient != nil {
					t.Fatal("expected nil httpClient when no caBundle is set")
				}
			} else {
				if httpClient == nil {
					t.Fatal("expected non-nil httpClient when caBundle is set")
				}
				transport, ok := httpClient.Transport.(*http.Transport)
				if !ok {
					t.Fatalf("expected *http.Transport, got %T", httpClient.Transport)
				}
				if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
					t.Fatal("expected TLSClientConfig.RootCAs to be set from caBundle")
				}
			}
		})
	}
}

func TestSolverForAcmeDNSPassesHTTPClientFromIssuerBundle(t *testing.T) {
	validCAPEM := mustGenerateCAPEM(t)

	const (
		issuerName = "test-issuer"
		ns         = "test-ns"
	)

	dnsProviders := newFakeDNSProviders()

	b := &test.Builder{
		KubeObjects: []runtime.Object{
			newSecret("acmedns-key", map[string][]byte{
				"acmedns.json": []byte("{}"),
			}, ns),
		},
		CertManagerObjects: []runtime.Object{
			gen.Issuer(issuerName,
				gen.SetIssuerNamespace(ns),
				gen.SetIssuerACME(cmacme.ACMEIssuer{
					Server:   "https://acme.example.com",
					CABundle: validCAPEM,
				}),
			),
		},
	}
	b.T = t
	b.InitWithRESTConfig()

	// Register the Issuers informer BEFORE Start() so the informer cache
	// gets populated with the test issuer.
	solver := &Solver{
		Context:                 b.Context,
		secretLister:            b.Context.KubeSharedInformerFactory.Secrets().Lister(),
		issuerLister:            b.Context.SharedInformerFactory.Certmanager().V1().Issuers().Lister(),
		dnsProviderConstructors: dnsProviders.constructors,
	}

	b.Start()
	b.Sync()
	defer b.Stop()

	challenge := &cmacme.Challenge{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
		},
		Spec: cmacme.ChallengeSpec{
			Solver: cmacme.ACMEChallengeSolver{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					AcmeDNS: &cmacme.ACMEIssuerDNS01ProviderAcmeDNS{
						Host: "https://acme-dns.example.com",
						AccountSecret: cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "acmedns-key",
							},
							Key: "acmedns.json",
						},
					},
				},
			},
			IssuerRef: cmmeta.IssuerReference{
				Name: issuerName,
			},
		},
	}

	_, _, err := solver.solverForChallenge(t.Context(), challenge)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(dnsProviders.calls) != 1 {
		t.Fatalf("expected 1 provider call, got %d", len(dnsProviders.calls))
	}

	call := dnsProviders.calls[0]
	if len(call.args) < 4 {
		t.Fatalf("expected at least 4 args, got %d", len(call.args))
	}

	httpClient, _ := call.args[3].(*http.Client)
	if httpClient == nil {
		t.Fatal("expected non-nil httpClient from issuer-level caBundle")
	}

	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", httpClient.Transport)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("expected TLSClientConfig.RootCAs to be set from issuer caBundle")
	}
}
