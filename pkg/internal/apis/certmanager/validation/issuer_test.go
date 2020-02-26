/*
Copyright 2019 The Jetstack cert-manager contributors.

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
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmacme "github.com/jetstack/cert-manager/pkg/internal/apis/acme"
	cmapi "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
	cmmeta "github.com/jetstack/cert-manager/pkg/internal/apis/meta"
)

var (
	validCloudDNSProvider = cmacme.ACMEIssuerDNS01ProviderCloudDNS{
		ServiceAccount: &validSecretKeyRef,
		Project:        "valid",
	}
	validSecretKeyRef = cmmeta.SecretKeySelector{
		LocalObjectReference: cmmeta.LocalObjectReference{
			Name: "valid",
		},
		Key: "validkey",
	}
	validCloudflareProvider = cmacme.ACMEIssuerDNS01ProviderCloudflare{
		APIKey: &validSecretKeyRef,
		Email:  "valid",
	}
	validACMEIssuer = cmacme.ACMEIssuer{
		Email:      "valid-email",
		Server:     "valid-server",
		PrivateKey: validSecretKeyRef,
	}
	validVaultIssuer = cmapi.VaultIssuer{
		Auth: cmapi.VaultAuth{
			TokenSecretRef: &validSecretKeyRef,
		},
		Server: "something",
		Path:   "a/b/c",
	}
)

func TestValidateVaultIssuerConfig(t *testing.T) {
	fldPath := field.NewPath("")
	scenarios := map[string]struct {
		spec *cmapi.VaultIssuer
		errs []*field.Error
	}{
		"valid vault issuer": {
			spec: &validVaultIssuer,
		},
		"vault issuer with missing fields": {
			spec: &cmapi.VaultIssuer{},
			errs: []*field.Error{
				field.Required(fldPath.Child("server"), ""),
				field.Required(fldPath.Child("path"), ""),
			},
		},
		"vault issuer with invalid fields": {
			spec: &cmapi.VaultIssuer{
				Server:   "something",
				Path:     "a/b/c",
				CABundle: []byte("invalid"),
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("caBundle"), "", "Specified CA bundle is invalid"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateVaultIssuerConfig(s.spec, fldPath)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected %v but got %v", expectedErr, e)
				}
			}
		})
	}
}

func TestValidateACMEIssuerConfig(t *testing.T) {
	fldPath := field.NewPath("")
	scenarios := map[string]struct {
		spec *cmacme.ACMEIssuer
		errs []*field.Error
	}{
		"valid acme issuer": {
			spec: &validACMEIssuer,
		},
		"acme solver with valid dns01 config": {
			spec: &cmacme.ACMEIssuer{
				Email:      "valid-email",
				Server:     "valid-server",
				PrivateKey: validSecretKeyRef,
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						DNS01: &cmacme.ACMEChallengeSolverDNS01{
							CloudDNS: &validCloudDNSProvider,
						},
					},
				},
			},
		},
		"acme solver with missing http01 config type": {
			spec: &cmacme.ACMEIssuer{
				Email:      "valid-email",
				Server:     "valid-server",
				PrivateKey: validSecretKeyRef,
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{},
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("solvers").Index(0).Child("http01"), "no HTTP01 solver type configured"),
			},
		},
		"acme solver with valid http01 config": {
			spec: &cmacme.ACMEIssuer{
				Email:      "valid-email",
				Server:     "valid-server",
				PrivateKey: validSecretKeyRef,
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
						},
					},
				},
			},
		},
		"acme issue with valid pod template ObjectMeta attributes": {
			spec: &cmacme.ACMEIssuer{
				Email:      "valid-email",
				Server:     "valid-server",
				PrivateKey: validSecretKeyRef,
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
								PodTemplate: &cmacme.ACMEChallengeSolverHTTP01IngressPodTemplate{
									ACMEChallengeSolverHTTP01IngressPodObjectMeta: cmacme.ACMEChallengeSolverHTTP01IngressPodObjectMeta{
										Labels: map[string]string{
											"valid_to_contain": "labels",
										},
										Annotations: map[string]string{
											"valid_to_contain": "annotations",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		"acme issue with valid pod template PodSpec attributes": {
			spec: &cmacme.ACMEIssuer{
				Email:      "valid-email",
				Server:     "valid-server",
				PrivateKey: validSecretKeyRef,
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
								PodTemplate: &cmacme.ACMEChallengeSolverHTTP01IngressPodTemplate{
									Spec: cmacme.ACMEChallengeSolverHTTP01IngressPodSpec{
										NodeSelector: map[string]string{
											"valid_to_contain": "nodeSelector",
										},
										Tolerations: []corev1.Toleration{
											{
												Key:      "valid_key",
												Operator: "Exists",
												Effect:   "NoSchedule",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		"acme issue with valid pod template ObjectMeta and PodSpec attributes": {
			spec: &cmacme.ACMEIssuer{
				Email:      "valid-email",
				Server:     "valid-server",
				PrivateKey: validSecretKeyRef,
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
								PodTemplate: &cmacme.ACMEChallengeSolverHTTP01IngressPodTemplate{
									ACMEChallengeSolverHTTP01IngressPodObjectMeta: cmacme.ACMEChallengeSolverHTTP01IngressPodObjectMeta{
										Labels: map[string]string{
											"valid_to_contain": "labels",
										},
									},
									Spec: cmacme.ACMEChallengeSolverHTTP01IngressPodSpec{
										NodeSelector: map[string]string{
											"valid_to_contain": "nodeSelector",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateACMEIssuerConfig(s.spec, fldPath)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected %v but got %v", expectedErr, e)
				}
			}
		})
	}
}

func TestValidateIssuerSpec(t *testing.T) {
	fldPath := field.NewPath("")
	scenarios := map[string]struct {
		spec *cmapi.IssuerSpec
		errs []*field.Error
	}{
		"valid ca issuer": {
			spec: &cmapi.IssuerSpec{
				IssuerConfig: cmapi.IssuerConfig{
					CA: &cmapi.CAIssuer{
						SecretName: "valid",
					},
				},
			},
		},
		"ca issuer without secret name specified": {
			spec: &cmapi.IssuerSpec{
				IssuerConfig: cmapi.IssuerConfig{
					CA: &cmapi.CAIssuer{},
				},
			},
			errs: []*field.Error{field.Required(fldPath.Child("ca", "secretName"), "")},
		},
		"valid self signed issuer": {
			spec: &cmapi.IssuerSpec{
				IssuerConfig: cmapi.IssuerConfig{
					SelfSigned: &cmapi.SelfSignedIssuer{},
				},
			},
		},
		"valid acme issuer": {
			spec: &cmapi.IssuerSpec{
				IssuerConfig: cmapi.IssuerConfig{
					ACME: &validACMEIssuer,
				},
			},
		},
		"valid vault issuer": {
			spec: &cmapi.IssuerSpec{
				IssuerConfig: cmapi.IssuerConfig{
					Vault: &validVaultIssuer,
				},
			},
		},
		"missing issuer config": {
			spec: &cmapi.IssuerSpec{
				IssuerConfig: cmapi.IssuerConfig{},
			},
			errs: []*field.Error{
				field.Required(fldPath, "at least one issuer must be configured"),
			},
		},
		"multiple issuers configured": {
			spec: &cmapi.IssuerSpec{
				IssuerConfig: cmapi.IssuerConfig{
					SelfSigned: &cmapi.SelfSignedIssuer{},
					CA: &cmapi.CAIssuer{
						SecretName: "valid",
					},
				},
			},
			errs: []*field.Error{
				field.Forbidden(fldPath.Child("selfSigned"), "may not specify more than one issuer type"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateIssuerSpec(s.spec, fldPath)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected %v but got %v", expectedErr, e)
				}
			}
		})
	}
}

func TestValidateACMEIssuerHTTP01Config(t *testing.T) {
	fldPath := field.NewPath("")
	scenarios := map[string]struct {
		isExpectedFailure bool
		cfg               *cmacme.ACMEChallengeSolverHTTP01
		errs              []*field.Error
	}{
		"ingress field specified": {
			cfg: &cmacme.ACMEChallengeSolverHTTP01{
				Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{Name: "abc"},
			},
		},
		"ingress class field specified": {
			cfg: &cmacme.ACMEChallengeSolverHTTP01{
				Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{Class: strPtr("abc")},
			},
		},
		"neither field specified": {
			cfg: &cmacme.ACMEChallengeSolverHTTP01{
				Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
			},
		},
		"no solver config type specified": {
			cfg: &cmacme.ACMEChallengeSolverHTTP01{},
			errs: []*field.Error{
				field.Required(fldPath, "no HTTP01 solver type configured"),
			},
		},
		"both fields specified": {
			cfg: &cmacme.ACMEChallengeSolverHTTP01{
				Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
					Name:  "abc",
					Class: strPtr("abc"),
				},
			},
			errs: []*field.Error{
				field.Forbidden(fldPath.Child("ingress"), "only one of 'name' or 'class' should be specified"),
			},
		},
		"acme issuer with valid http01 service config serviceType ClusterIP": {
			cfg: &cmacme.ACMEChallengeSolverHTTP01{
				Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
					ServiceType: corev1.ServiceType("ClusterIP"),
				},
			},
		},
		"acme issuer with valid http01 service config serviceType NodePort": {
			cfg: &cmacme.ACMEChallengeSolverHTTP01{
				Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
					ServiceType: corev1.ServiceType("NodePort"),
				},
			},
		},
		"acme issuer with valid http01 service config serviceType (empty string)": {
			cfg: &cmacme.ACMEChallengeSolverHTTP01{
				Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
					ServiceType: corev1.ServiceType(""),
				},
			},
		},
		"acme issuer with invalid http01 service config": {
			cfg: &cmacme.ACMEChallengeSolverHTTP01{
				Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
					ServiceType: corev1.ServiceType("InvalidServiceType"),
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("ingress", "serviceType"), corev1.ServiceType("InvalidServiceType"), `must be empty, "ClusterIP" or "NodePort"`),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateACMEIssuerChallengeSolverHTTP01Config(s.cfg, fldPath)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected %v but got %v", expectedErr, e)
				}
			}
		})
	}
}

func TestValidateACMEIssuerDNS01Config(t *testing.T) {
	fldPath := field.NewPath("test")
	scenarios := map[string]struct {
		cfg  *cmacme.ACMEChallengeSolverDNS01
		errs []*field.Error
	}{

		"clouddns serviceAccount field not set should be allowed for ambient auth": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				CloudDNS: &cmacme.ACMEIssuerDNS01ProviderCloudDNS{
					Project: "valid",
				},
			},
		},
		"missing cloudflare api token or key": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
					Email: "valid",
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("cloudflare"), "apiKeySecretRef or apiTokenSecretRef is required"),
			},
		},
		"both cloudflare api token and key specified": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
					Email:    "valid",
					APIToken: &validSecretKeyRef,
					APIKey:   &validSecretKeyRef,
				},
			},
			errs: []*field.Error{
				field.Forbidden(fldPath.Child("cloudflare"), "apiKeySecretRef and apiTokenSecretRef cannot both be specified"),
			},
		},
		"valid akamai config": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				Akamai: &cmacme.ACMEIssuerDNS01ProviderAkamai{
					AccessToken:           validSecretKeyRef,
					ClientSecret:          validSecretKeyRef,
					ClientToken:           validSecretKeyRef,
					ServiceConsumerDomain: "abc",
				},
			},
			errs: []*field.Error{},
		},
		"valid rfc2136 config": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
					Nameserver: "127.0.0.1",
				},
			},
			errs: []*field.Error{},
		},

		"rfc2136 provider invalid nameserver": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
					Nameserver: "dns.example.com",
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("rfc2136", "nameserver"), "", "Nameserver invalid. Check the documentation for details."),
			},
		},
		"rfc2136 provider using case-camel in algorithm": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
					Nameserver:    "127.0.0.1",
					TSIGAlgorithm: "HmAcMd5",
				},
			},
			errs: []*field.Error{},
		},
		"rfc2136 provider using unsupported algorithm": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
					Nameserver:    "127.0.0.1",
					TSIGAlgorithm: "HAMMOCK",
				},
			},
			errs: []*field.Error{
				field.NotSupported(fldPath.Child("rfc2136", "tsigAlgorithm"), "", supportedTSIGAlgorithms),
			},
		},
		"rfc2136 provider TSIGSecret provided but no TSIGKeyName": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
					Nameserver: "127.0.0.1",
					TSIGSecret: validSecretKeyRef,
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("rfc2136", "tsigKeyName"), ""),
			},
		},
		"multiple providers configured": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				CloudDNS: &cmacme.ACMEIssuerDNS01ProviderCloudDNS{
					Project: "something",
				},
				AcmeDNS: &cmacme.ACMEIssuerDNS01ProviderAcmeDNS{},
			},
			errs: []*field.Error{
				field.Forbidden(fldPath, "may not specify more than one provider type"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateACMEChallengeSolverDNS01(s.cfg, fldPath)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected %v but got %v", expectedErr, e)
				}
			}
		})
	}
}
