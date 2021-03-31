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

package validation

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

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
		"acme issuer with missing fields": {
			spec: &cmacme.ACMEIssuer{},
			errs: []*field.Error{
				field.Required(fldPath.Child("privateKeySecretRef", "name"), "private key secret name is a required field"),
				field.Required(fldPath.Child("server"), "acme server URL is a required field"),
			},
		},
		"acme solver without any config": {
			spec: &cmacme.ACMEIssuer{
				Email:      "valid-email",
				Server:     "valid-server",
				PrivateKey: validSecretKeyRef,
				Solvers: []cmacme.ACMEChallengeSolver{
					{},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("solvers").Index(0), "no solver type configured"),
			},
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
		"acme solver with empty external account binding fields": {
			spec: &cmacme.ACMEIssuer{
				Email:                  "valid-email",
				Server:                 "valid-server",
				PrivateKey:             validSecretKeyRef,
				ExternalAccountBinding: &cmacme.ACMEExternalAccountBinding{},
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						DNS01: &cmacme.ACMEChallengeSolverDNS01{
							CloudDNS: &validCloudDNSProvider,
						},
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("externalAccountBinding.keyID"), "the keyID field is required when using externalAccountBinding"),
				field.Required(fldPath.Child("externalAccountBinding.keySecretRef.name"), "secret name is required"),
				field.Required(fldPath.Child("externalAccountBinding.keySecretRef.key"), "secret key is required"),
				field.Required(fldPath.Child("externalAccountBinding.keyAlgorithm"), "the keyAlgorithm field is required when using externalAccountBinding"),
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
		errs field.ErrorList
	}{
		"valid ca issuer": {
			spec: &cmapi.IssuerSpec{
				IssuerConfig: cmapi.IssuerConfig{
					CA: &cmapi.CAIssuer{
						SecretName: "valid",
					},
				},
			},
			errs: []*field.Error{},
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
			errs: []*field.Error{},
		},
		"valid acme issuer": {
			spec: &cmapi.IssuerSpec{
				IssuerConfig: cmapi.IssuerConfig{
					ACME: &validACMEIssuer,
				},
			},
			errs: []*field.Error{},
		},
		"valid vault issuer": {
			spec: &cmapi.IssuerSpec{
				IssuerConfig: cmapi.IssuerConfig{
					Vault: &validVaultIssuer,
				},
			},
			errs: []*field.Error{},
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
		"valid ocsp url": {
			spec: &cmapi.IssuerSpec{
				IssuerConfig: cmapi.IssuerConfig{
					CA: &cmapi.CAIssuer{
						SecretName:  "valid",
						OCSPServers: []string{"http://ocsp.int-x3.letsencrypt.org"},
					},
				},
			},
			errs: []*field.Error{},
		},
		"invalid ocsp url": {
			spec: &cmapi.IssuerSpec{
				IssuerConfig: cmapi.IssuerConfig{
					CA: &cmapi.CAIssuer{
						SecretName:  "valid",
						OCSPServers: []string{""},
					},
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("ca", "ocspServer").Index(0), "", `must be a valid URL, e.g., http://ocsp.int-x3.letsencrypt.org`),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			gotErrs := ValidateIssuerSpec(s.spec, fldPath)
			assert.Equal(t, s.errs, gotErrs)
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
		"missing clouddns project": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				CloudDNS: &cmacme.ACMEIssuerDNS01ProviderCloudDNS{
					ServiceAccount: &validSecretKeyRef,
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("cloudDNS", "project"), ""),
			},
		},
		"missing clouddns service account key": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				CloudDNS: &cmacme.ACMEIssuerDNS01ProviderCloudDNS{
					Project: "valid",
					ServiceAccount: &cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{Name: "something"},
						Key:                  "",
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("cloudDNS", "serviceAccountSecretRef", "key"), "secret key is required"),
			},
		},
		"missing clouddns service account name": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				CloudDNS: &cmacme.ACMEIssuerDNS01ProviderCloudDNS{
					Project: "valid",
					ServiceAccount: &cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{Name: ""},
						Key:                  "something",
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("cloudDNS", "serviceAccountSecretRef", "name"), "secret name is required"),
			},
		},
		"clouddns serviceAccount field not set should be allowed for ambient auth": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				CloudDNS: &cmacme.ACMEIssuerDNS01ProviderCloudDNS{
					Project: "valid",
				},
			},
		},
		"missing cloudflare api key fields": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
					Email:  "valid",
					APIKey: &cmmeta.SecretKeySelector{},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("cloudflare", "apiKeySecretRef", "name"), "secret name is required"),
				field.Required(fldPath.Child("cloudflare", "apiKeySecretRef", "key"), "secret key is required"),
			},
		},
		"missing cloudflare api token fields": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
					Email:    "valid",
					APIToken: &cmmeta.SecretKeySelector{},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("cloudflare", "apiTokenSecretRef", "name"), "secret name is required"),
				field.Required(fldPath.Child("cloudflare", "apiTokenSecretRef", "key"), "secret key is required"),
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
		"missing cloudflare email": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
					APIKey: &validSecretKeyRef,
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("cloudflare", "email"), ""),
			},
		},
		"missing route53 region": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("route53", "region"), ""),
			},
		},
		"missing provider config": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{},
			errs: []*field.Error{
				field.Required(fldPath, "no DNS01 provider configured"),
			},
		},
		"missing azuredns config": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("azureDNS", "subscriptionID"), ""),
				field.Required(fldPath.Child("azureDNS", "resourceGroupName"), ""),
			},
		},
		"invalid azuredns environment": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
					Environment: "an env",
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("azureDNS", "subscriptionID"), ""),
				field.Required(fldPath.Child("azureDNS", "resourceGroupName"), ""),
				field.Invalid(fldPath.Child("azureDNS", "environment"), cmacme.AzureDNSEnvironment("an env"),
					"must be either empty or one of AzurePublicCloud, AzureChinaCloud, AzureGermanCloud or AzureUSGovernmentCloud"),
			},
		},
		"invalid azuredns missing clientSecret and tenantID": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
					ClientID: "some-client-id",
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("azureDNS", "clientSecretSecretRef"), ""),
				field.Required(fldPath.Child("azureDNS", "tenantID"), ""),
				field.Required(fldPath.Child("azureDNS", "subscriptionID"), ""),
				field.Required(fldPath.Child("azureDNS", "resourceGroupName"), ""),
			},
		},
		"invalid azuredns missing clientID and tenantID": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
					ClientSecret: &cmmeta.SecretKeySelector{
						Key: "some-key",
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: "some-secret-name",
						},
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("azureDNS", "clientID"), ""),
				field.Required(fldPath.Child("azureDNS", "tenantID"), ""),
				field.Required(fldPath.Child("azureDNS", "subscriptionID"), ""),
				field.Required(fldPath.Child("azureDNS", "resourceGroupName"), ""),
			},
		},
		"invalid azuredns missing clientID and clientSecret": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
					TenantID: "some-tenant-id",
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("azureDNS", "clientID"), ""),
				field.Required(fldPath.Child("azureDNS", "clientSecretSecretRef"), ""),
				field.Required(fldPath.Child("azureDNS", "subscriptionID"), ""),
				field.Required(fldPath.Child("azureDNS", "resourceGroupName"), ""),
			},
		},
		"invalid azuredns missing clientID": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
					ClientSecret: &cmmeta.SecretKeySelector{
						Key: "some-key",
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: "some-secret-name",
						},
					},
					TenantID: "some-tenant-id",
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("azureDNS", "clientID"), ""),
				field.Required(fldPath.Child("azureDNS", "subscriptionID"), ""),
				field.Required(fldPath.Child("azureDNS", "resourceGroupName"), ""),
			},
		},
		"invalid azuredns missing clientSecret": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
					TenantID: "some-tenant-id",
					ClientID: "some-client-id",
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("azureDNS", "clientSecretSecretRef"), ""),
				field.Required(fldPath.Child("azureDNS", "subscriptionID"), ""),
				field.Required(fldPath.Child("azureDNS", "resourceGroupName"), ""),
			},
		},
		"invalid azuredns clientSecret missing key": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
					TenantID: "some-tenant-id",
					ClientID: "some-client-id",
					ClientSecret: &cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: "some-secret-name",
						},
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("azureDNS", "clientSecretSecretRef", "key"), "secret key is required"),
				field.Required(fldPath.Child("azureDNS", "subscriptionID"), ""),
				field.Required(fldPath.Child("azureDNS", "resourceGroupName"), ""),
			},
		},
		"invalid azuredns clientSecret missing secret name": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
					TenantID: "some-tenant-id",
					ClientID: "some-client-id",
					ClientSecret: &cmmeta.SecretKeySelector{
						Key: "some-key",
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("azureDNS", "clientSecretSecretRef", "name"), "secret name is required"),
				field.Required(fldPath.Child("azureDNS", "subscriptionID"), ""),
				field.Required(fldPath.Child("azureDNS", "resourceGroupName"), ""),
			},
		},
		"invalid azuredns missing tenantID": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
					ClientID: "some-client-id",
					ClientSecret: &cmmeta.SecretKeySelector{
						Key: "some-key",
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: "some-secret-name",
						},
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("azureDNS", "tenantID"), ""),
				field.Required(fldPath.Child("azureDNS", "subscriptionID"), ""),
				field.Required(fldPath.Child("azureDNS", "resourceGroupName"), ""),
			},
		},
		"missing akamai config": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				Akamai: &cmacme.ACMEIssuerDNS01ProviderAkamai{},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("akamai", "accessToken", "name"), "secret name is required"),
				field.Required(fldPath.Child("akamai", "accessToken", "key"), "secret key is required"),
				field.Required(fldPath.Child("akamai", "clientSecret", "name"), "secret name is required"),
				field.Required(fldPath.Child("akamai", "clientSecret", "key"), "secret key is required"),
				field.Required(fldPath.Child("akamai", "clientToken", "name"), "secret name is required"),
				field.Required(fldPath.Child("akamai", "clientToken", "key"), "secret key is required"),
				field.Required(fldPath.Child("akamai", "serviceConsumerDomain"), ""),
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
		"rfc2136 provider with missing nameserver": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("rfc2136", "nameserver"), ""),
			},
		},
		"rfc2136 provider with IPv4 nameserver": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
					Nameserver: "127.0.0.1",
				},
			},
			errs: []*field.Error{},
		},
		"rfc2136 provider with unenclosed IPv6 nameserver": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
					Nameserver: "2001:db8::1",
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("rfc2136", "nameserver"), "2001:db8::1", "nameserver must be set in the form host:port where host is an IPv4 address, an enclosed IPv6 address or a hostname and port is an optional port number."),
			},
		},
		"rfc2136 provider with empty IPv6 nameserver": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
					Nameserver: "[]:53",
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("rfc2136", "nameserver"), "[]:53", "nameserver must be set in the form host:port where host is an IPv4 address, an enclosed IPv6 address or a hostname and port is an optional port number."),
			},
		},
		"rfc2136 provider with IPv6 nameserver": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
					Nameserver: "[2001:db8::1]",
				},
			},
			errs: []*field.Error{},
		},
		"rfc2136 provider with FQDN nameserver": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
					Nameserver: "dns.example.com",
				},
			},
			errs: []*field.Error{},
		},
		"rfc2136 provider with hostname nameserver": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
					Nameserver: "dns",
				},
			},
			errs: []*field.Error{},
		},
		"rfc2136 provider with nameserver without host": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
					Nameserver: ":53",
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("rfc2136", "nameserver"), ":53", "nameserver must be set in the form host:port where host is an IPv4 address, an enclosed IPv6 address or a hostname and port is an optional port number."),
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
		"rfc2136 provider TSIGKeyName provided but no TSIGSecret": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
					Nameserver:  "127.0.0.1",
					TSIGKeyName: "some-name",
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("rfc2136", "tsigSecretSecretRef", "name"), "secret name is required"),
				field.Required(fldPath.Child("rfc2136", "tsigSecretSecretRef", "key"), "secret key is required"),
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
				Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{},
			},
			errs: []*field.Error{
				field.Forbidden(fldPath.Child("cloudflare"), "may not specify more than one provider type"),
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

func TestValidateSecretKeySelector(t *testing.T) {
	validName := cmmeta.LocalObjectReference{Name: "name"}
	validKey := "key"
	// invalidName := cmmeta.LocalObjectReference{"-name-"}
	// invalidKey := "-key-"
	fldPath := field.NewPath("")
	scenarios := map[string]struct {
		isExpectedFailure bool
		selector          *cmmeta.SecretKeySelector
		errs              []*field.Error
	}{
		"valid selector": {
			selector: &cmmeta.SecretKeySelector{
				LocalObjectReference: validName,
				Key:                  validKey,
			},
		},
		// "invalid name": {
		// 	isExpectedFailure: true,
		// 	selector: &cmmeta.SecretKeySelector{
		// 		LocalObjectReference: invalidName,
		// 		Key:                  validKey,
		// 	},
		// },
		// "invalid key": {
		// 	isExpectedFailure: true,
		// 	selector: &cmmeta.SecretKeySelector{
		// 		LocalObjectReference: validName,
		// 		Key:                  invalidKey,
		// 	},
		// },
		"missing name": {
			selector: &cmmeta.SecretKeySelector{
				Key: validKey,
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("name"), "secret name is required"),
			},
		},
		"missing key": {
			selector: &cmmeta.SecretKeySelector{
				LocalObjectReference: validName,
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("key"), "secret key is required"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateSecretKeySelector(s.selector, fldPath)
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

func TestValidateVenafiIssuerConfig(t *testing.T) {
	fldPath := field.NewPath("test")
	scenarios := map[string]struct {
		cfg  *cmapi.VenafiIssuer
		errs []*field.Error
	}{
		"valid": {
			cfg: &cmapi.VenafiIssuer{
				Zone: "a\\b\\c",
				TPP: &cmapi.VenafiTPP{
					URL: "https://tpp.example.com/vedsdk",
				},
			},
		},
		"missing zone": {
			cfg: &cmapi.VenafiIssuer{
				Zone: "",
				TPP: &cmapi.VenafiTPP{
					URL: "https://tpp.example.com/vedsdk",
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("zone"), ""),
			},
		},
		"missing configuration": {
			cfg: &cmapi.VenafiIssuer{
				Zone: "a\\b\\c",
			},
			errs: []*field.Error{
				field.Required(fldPath, "please supply one of: tpp, cloud"),
			},
		},
		"multiple configuration": {
			cfg: &cmapi.VenafiIssuer{
				Zone: "a\\b\\c",
				TPP: &cmapi.VenafiTPP{
					URL: "https://tpp.example.com/vedsdk",
				},
				Cloud: &cmapi.VenafiCloud{},
			},
			errs: []*field.Error{
				field.Forbidden(fldPath, "please supply one of: tpp, cloud"),
			},
		},
	}

	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateVenafiIssuerConfig(s.cfg, fldPath)
			if len(errs) != len(s.errs) {
				t.Fatalf("Expected %v but got %v", s.errs, errs)
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

func TestValidateVenafiTPP(t *testing.T) {
	fldPath := field.NewPath("test")
	scenarios := map[string]struct {
		cfg  *cmapi.VenafiTPP
		errs []*field.Error
	}{
		"valid": {
			cfg: &cmapi.VenafiTPP{
				URL: "https://tpp.example.com/vedsdk",
			},
		},
		"missing url": {
			cfg: &cmapi.VenafiTPP{},
			errs: []*field.Error{
				field.Required(fldPath.Child("url"), ""),
			},
		},
	}

	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateVenafiTPP(s.cfg, fldPath)
			if len(errs) != len(s.errs) {
				t.Fatalf("Expected %v but got %v", s.errs, errs)
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
