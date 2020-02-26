/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package validation

import (
	"context"
	"errors"
	"testing"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha3"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jetstack/cert-manager/pkg/api"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha3"
	"github.com/jetstack/cert-manager/test/integration/framework"
)

var issuerGVK = schema.GroupVersionKind{
	Group:   "cert-manager.io",
	Version: "v1alpha3",
	Kind:    "Issuer",
}

func TestValidationIssuer(t *testing.T) {
	tests := map[string]struct {
		input       runtime.Object
		error       error
		expectError bool
	}{
		"reject acme issuer with missing fields": {
			input: &v1alpha3.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha3.IssuerSpec{
					IssuerConfig: v1alpha3.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{},
					},
				},
			},
			expectError: true,
			error:       errors.New(`admission webhook "webhook.cert-manager.io" denied the request: [spec.acme.privateKeySecretRef.name: Required value: private key secret name is a required field, spec.acme.server: Required value: acme server URL is a required field]`),
		},
		"reject acme issuer having empty solver": {
			input: &v1alpha3.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha3.IssuerSpec{
					IssuerConfig: v1alpha3.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Email:                  "valid@email.com",
							Server:                 "acme.example.com",
							SkipTLSVerify:          false,
							ExternalAccountBinding: nil,
							PrivateKey: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{Name: "secret"},
								Key:                  "key",
							},
							Solvers: []cmacme.ACMEChallengeSolver{{}},
						},
					},
				},
			},
			expectError: true,
			error:       errors.New(`admission webhook "webhook.cert-manager.io" denied the request: spec.acme.solvers[0]: Required value: no solver type configured`),
		},
		"reject missing clouddns project": {
			input: &v1alpha3.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha3.IssuerSpec{
					IssuerConfig: v1alpha3.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Email:                  "valid@email.com",
							Server:                 "acme.example.com",
							SkipTLSVerify:          false,
							ExternalAccountBinding: nil,
							PrivateKey: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{Name: "secret"},
								Key:                  "key",
							},
							Solvers: []cmacme.ACMEChallengeSolver{
								{
									DNS01: &cmacme.ACMEChallengeSolverDNS01{
										CloudDNS: &cmacme.ACMEIssuerDNS01ProviderCloudDNS{
											Project: "",
											ServiceAccount: &cmmeta.SecretKeySelector{
												LocalObjectReference: cmmeta.LocalObjectReference{Name: "test"},
												Key:                  "test",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
			error:       errors.New(`admission webhook "webhook.cert-manager.io" denied the request: spec.acme.solvers[0].dns01.clouddns.project: Required value`),
		},
		"reject for missing cloudflare api key": {
			input: &v1alpha3.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha3.IssuerSpec{
					IssuerConfig: v1alpha3.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Email:                  "valid@email.com",
							Server:                 "acme.example.com",
							SkipTLSVerify:          false,
							ExternalAccountBinding: nil,
							PrivateKey: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{Name: "secret"},
								Key:                  "key",
							},
							Solvers: []cmacme.ACMEChallengeSolver{
								{
									DNS01: &cmacme.ACMEChallengeSolverDNS01{
										Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
											Email: "valid@example.com",
										},
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
			error:       errors.New(`admission webhook "webhook.cert-manager.io" denied the request: spec.acme.solvers[0].dns01.cloudflare: Required value: apiKeySecretRef or apiTokenSecretRef is required`),
		},
		"reject for having multiple valid solvers": {
			input: &v1alpha3.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha3.IssuerSpec{
					IssuerConfig: v1alpha3.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Email:                  "valid@email.com",
							Server:                 "acme.example.com",
							SkipTLSVerify:          false,
							ExternalAccountBinding: nil,
							PrivateKey: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{Name: "secret"},
								Key:                  "key",
							},
							Solvers: []cmacme.ACMEChallengeSolver{
								{
									DNS01: &cmacme.ACMEChallengeSolverDNS01{
										RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
											Nameserver:  "127.0.0.1",
											TSIGKeyName: "some-name",
											TSIGSecret: cmmeta.SecretKeySelector{
												LocalObjectReference: cmmeta.LocalObjectReference{Name: "valid"},
												Key:                  "valid",
											},
										},
										Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
											Email: "valid@example.com",
											APIToken: &cmmeta.SecretKeySelector{
												LocalObjectReference: cmmeta.LocalObjectReference{Name: "valid"},
												Key:                  "valid",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
			error:       errors.New(`admission webhook "webhook.cert-manager.io" denied the request: spec.acme.solvers[0].dns01: Forbidden: may not specify more than one provider type`),
		},
		"reject rfc2136 provider using unsupported algorithm": {
			input: &v1alpha3.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha3.IssuerSpec{
					IssuerConfig: v1alpha3.IssuerConfig{
						ACME: &cmacme.ACMEIssuer{
							Email:                  "valid@email.com",
							Server:                 "acme.example.com",
							SkipTLSVerify:          false,
							ExternalAccountBinding: nil,
							PrivateKey: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{Name: "secret"},
								Key:                  "key",
							},
							Solvers: []cmacme.ACMEChallengeSolver{
								{
									DNS01: &cmacme.ACMEChallengeSolverDNS01{
										RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
											Nameserver:    "127.0.0.1",
											TSIGAlgorithm: "HAMMOCK",
										},
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
			error:       errors.New(`admission webhook "webhook.cert-manager.io" denied the request: spec.acme.solvers[0].dns01.rfc2136.tsigAlgorithm: Unsupported value: "": supported values: "HMACMD5", "HMACSHA1", "HMACSHA256", "HMACSHA512"`),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cert := test.input.(*v1alpha3.Issuer)
			cert.SetGroupVersionKind(issuerGVK)

			config, stop := framework.RunControlPlane(t)
			defer stop()
			framework.WaitForOpenAPIResourcesToBeLoaded(t, config, issuerGVK)

			// create the object to get any errors back from the webhook
			cl, err := client.New(config, client.Options{Scheme: api.Scheme})
			if err != nil {
				t.Fatal(err)
			}

			err = cl.Create(context.Background(), cert)

			if !test.expectError && err == nil {
				t.Fatalf("Didn't expect error and got error: %v", err)
			} else if test.expectError && err == nil {
				t.Errorf("Expected error %v but got nil", test.error)

			} else if test.expectError && err.Error() != test.error.Error() {
				t.Errorf("Expected error %v but got %v", test.error, err)
			}
		})
	}
}
