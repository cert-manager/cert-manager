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
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"

	cmacme "github.com/cert-manager/cert-manager/internal/apis/acme"
	cmapi "github.com/cert-manager/cert-manager/internal/apis/certmanager"
	cmmeta "github.com/cert-manager/cert-manager/internal/apis/meta"
	pubcmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	unitcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
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
	// TODO (JS): Missing test for validCloudflareProvider
	// nolint: unused
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
	caBundle := unitcrypto.MustCreateCryptoBundle(t,
		&pubcmapi.Certificate{Spec: pubcmapi.CertificateSpec{CommonName: "test"}},
		clock.RealClock{},
	).CertBytes

	fldPath := field.NewPath("spec")
	scenarios := map[string]struct {
		spec *cmapi.VaultIssuer
		errs []*field.Error
	}{
		"vault issuer defines both caBundle and caBundleSecretRef": {
			spec: &cmapi.VaultIssuer{
				Server:   "https://vault.example.com",
				Path:     "secret/path",
				CABundle: caBundle,
				CABundleSecretRef: &cmmeta.SecretKeySelector{
					Key: "ca.crt",
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: "test-secret",
					},
				},
				Auth: cmapi.VaultAuth{
					TokenSecretRef: &validSecretKeyRef,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("caBundle"), "<snip>", "specified caBundle and caBundleSecretRef cannot be used together"),
				field.Invalid(fldPath.Child("caBundleSecretRef"), "test-secret", "specified caBundleSecretRef and caBundle cannot be used together"),
			},
		},
		"valid vault issuer": {
			spec: &validVaultIssuer,
		},
		"vault issuer with missing fields": {
			spec: &cmapi.VaultIssuer{},
			errs: []*field.Error{
				field.Required(fldPath.Child("server"), ""),
				field.Required(fldPath.Child("path"), ""),
				field.Required(fldPath.Child("auth"), "please supply one of: appRole, kubernetes, tokenSecretRef, clientCertificate"),
			},
		},
		"vault issuer with a CA bundle containing no valid certificates": {
			spec: &cmapi.VaultIssuer{
				Server:   "something",
				Path:     "a/b/c",
				CABundle: []byte("invalid"),
				Auth: cmapi.VaultAuth{
					TokenSecretRef: &validSecretKeyRef,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("caBundle"), "<snip>", "cert bundle didn't contain any valid certificates"),
			},
		},
		"vault issuer define clientCertSecretRef but not clientKeySecretRef": {
			spec: &cmapi.VaultIssuer{
				Server: "https://vault.example.com",
				Path:   "secret/path",
				CABundleSecretRef: &cmmeta.SecretKeySelector{
					Key: "ca.crt",
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: "test-secret",
					},
				},
				ClientCertSecretRef: &cmmeta.SecretKeySelector{
					Key: "tls.crt",
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: "test-secret",
					},
				},
				Auth: cmapi.VaultAuth{
					TokenSecretRef: &validSecretKeyRef,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("clientKeySecretRef"), "<snip>", "clientKeySecretRef must be provided when defining the clientCertSecretRef"),
			},
		},
		"vault issuer define clientKeySecretRef but not clientCertSecretRef": {
			spec: &cmapi.VaultIssuer{
				Server: "https://vault.example.com",
				Path:   "secret/path",
				CABundleSecretRef: &cmmeta.SecretKeySelector{
					Key: "ca.crt",
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: "test-secret",
					},
				},
				ClientKeySecretRef: &cmmeta.SecretKeySelector{
					Key: "tls.key",
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: "test-secret",
					},
				},
				Auth: cmapi.VaultAuth{
					TokenSecretRef: &validSecretKeyRef,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("clientCertSecretRef"), "<snip>", "clientCertSecretRef must be provided when defining the clientKeySecretRef"),
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

func TestValidateVaultIssuerAuth(t *testing.T) {
	fldPath := field.NewPath("spec.auth")
	scenarios := map[string]struct {
		auth *cmapi.VaultAuth
		errs []*field.Error
	}{
		// For backwards compatibility, we allow the user to set all auth types.
		// We have documented in the API the order of precedence.
		"valid auth: all three auth types can be set simultaneously": {
			auth: &cmapi.VaultAuth{
				AppRole: &cmapi.VaultAppRole{
					RoleId: "role-id",
					SecretRef: cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{Name: "secret"},
						Key:                  "key",
					},
					Path: "path",
				},
				TokenSecretRef: &validSecretKeyRef,
				Kubernetes: &cmapi.VaultKubernetesAuth{
					Path: "path",
					Role: "role",
					ServiceAccountRef: &cmapi.ServiceAccountRef{
						Name: "service-account",
					},
				},
			},
		},
		"valid auth.tokenSecretRef": {
			auth: &cmapi.VaultAuth{
				TokenSecretRef: &cmmeta.SecretKeySelector{
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: "secret",
					},
					Key: "key",
				},
			},
		},
		// The default value for auth.tokenSecretRef.key is 'token'. This
		// behavior is not documented in the API reference, but we keep it for
		// backward compatibility.
		"invalid auth.tokenSecretRef: key can be omitted": {
			auth: &cmapi.VaultAuth{
				TokenSecretRef: &cmmeta.SecretKeySelector{
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: "secret",
					},
				},
			},
		},
		"valid auth.appRole": {
			auth: &cmapi.VaultAuth{
				AppRole: &cmapi.VaultAppRole{
					RoleId: "role-id",
					SecretRef: cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{Name: "secret"},
						Key:                  "key",
					},
					Path: "path",
				},
			},
		},
		// TODO(mael): The reason we allow the user to omit the key but we say
		// in the documentation that "key must be specified" is because the
		// controller-side validation doesn't check that the key is empty. We
		// should add a check for that.
		"valid auth.appRole: key can be omitted": {
			auth: &cmapi.VaultAuth{
				AppRole: &cmapi.VaultAppRole{
					RoleId: "role-id",
					SecretRef: cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{Name: "secret"},
					},
					Path: "path",
				},
			},
		},
		"invalid auth.appRole: roleId is required": {
			auth: &cmapi.VaultAuth{
				AppRole: &cmapi.VaultAppRole{
					SecretRef: cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{Name: "secret"},
						Key:                  "key",
					},
					Path: "path",
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("appRole").Child("roleId"), ""),
			},
		},
		"valid auth.clientCertificate: all fields can be empty": {
			auth: &cmapi.VaultAuth{
				ClientCertificate: &cmapi.VaultClientCertificateAuth{},
			},
		},
		// The field auth.kubernetes.secretRef.key defaults to 'token' if
		// not specified.
		"valid auth.kubernetes.secretRef: key can be left empty": {
			auth: &cmapi.VaultAuth{
				Kubernetes: &cmapi.VaultKubernetesAuth{
					SecretRef: cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{Name: "secret"},
					},
					Role: "role",
				},
			},
		},
		"valid auth.kubernetes.serviceAccountRef": {
			auth: &cmapi.VaultAuth{
				Kubernetes: &cmapi.VaultKubernetesAuth{
					Path: "path",
					Role: "role",
					ServiceAccountRef: &cmapi.ServiceAccountRef{
						Name: "service-account",
					},
				},
			},
		},
		"invalid auth.kubernetes: role is required": {
			auth: &cmapi.VaultAuth{
				Kubernetes: &cmapi.VaultKubernetesAuth{
					Path: "path",
					ServiceAccountRef: &cmapi.ServiceAccountRef{
						Name: "service-account",
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("kubernetes").Child("role"), ""),
			},
		},
		"invalid auth.kubernetes: secretRef and serviceAccountRef mutually exclusive": {
			auth: &cmapi.VaultAuth{
				Kubernetes: &cmapi.VaultKubernetesAuth{
					SecretRef: cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{Name: "secret"},
					},
					ServiceAccountRef: &cmapi.ServiceAccountRef{
						Name: "service-account",
					},
					Role: "role",
				},
			},
			errs: []*field.Error{
				field.Forbidden(fldPath.Child("kubernetes"), "please supply one of: secretRef, serviceAccountRef"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateVaultIssuerAuth(s.auth, fldPath)
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
	fldPath := (*field.Path)(nil)

	caBundle := unitcrypto.MustCreateCryptoBundle(t,
		&pubcmapi.Certificate{Spec: pubcmapi.CertificateSpec{CommonName: "test"}},
		clock.RealClock{},
	).CertBytes

	scenarios := map[string]struct {
		spec     *cmacme.ACMEIssuer
		errs     []*field.Error
		warnings []string
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
		"acme issuer with an invalid CA bundle": {
			spec: &cmacme.ACMEIssuer{
				Email:      "valid-email",
				Server:     "valid-server",
				CABundle:   []byte("abc123"),
				PrivateKey: validSecretKeyRef,
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						DNS01: &cmacme.ACMEChallengeSolverDNS01{
							CloudDNS: &validCloudDNSProvider,
						},
					},
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("caBundle"), "", "cert bundle didn't contain any valid certificates"),
			},
		},
		"acme issuer with both a CA bundle and SkipTLSVerify": {
			spec: &cmacme.ACMEIssuer{
				Email:         "valid-email",
				Server:        "valid-server",
				CABundle:      caBundle,
				SkipTLSVerify: true,
				PrivateKey:    validSecretKeyRef,
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						DNS01: &cmacme.ACMEChallengeSolverDNS01{
							CloudDNS: &validCloudDNSProvider,
						},
					},
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("caBundle"), "", "caBundle and skipTLSVerify are mutually exclusive and cannot both be set"),
				field.Invalid(fldPath.Child("skipTLSVerify"), true, "caBundle and skipTLSVerify are mutually exclusive and cannot both be set"),
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
		"acme solver with external account binding missing required fields": {
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
			},
		},
		"acme solver with a valid external account binding and keyAlgorithm not set": {
			spec: &cmacme.ACMEIssuer{
				Email:      "valid-email",
				Server:     "valid-server",
				PrivateKey: validSecretKeyRef,
				ExternalAccountBinding: &cmacme.ACMEExternalAccountBinding{
					KeyID: "test",
					Key:   validSecretKeyRef,
				},
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						DNS01: &cmacme.ACMEChallengeSolverDNS01{
							CloudDNS: &validCloudDNSProvider,
						},
					},
				},
			},
		},
		"acme solver with a valid external account binding and keyAlgorithm set": {
			spec: &cmacme.ACMEIssuer{
				Email:      "valid-email",
				Server:     "valid-server",
				PrivateKey: validSecretKeyRef,
				ExternalAccountBinding: &cmacme.ACMEExternalAccountBinding{
					KeyID:        "test",
					Key:          validSecretKeyRef,
					KeyAlgorithm: cmacme.HS384,
				},
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						DNS01: &cmacme.ACMEChallengeSolverDNS01{
							CloudDNS: &validCloudDNSProvider,
						},
					},
				},
			},
			warnings: []string{deprecatedACMEEABKeyAlgorithmField},
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
		"acme solver with valid http01 ingress config": {
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
		"acme solver with valid http01 gateway config": {
			spec: &cmacme.ACMEIssuer{
				Email:      "valid-email",
				Server:     "valid-server",
				PrivateKey: validSecretKeyRef,
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							GatewayHTTPRoute: &cmacme.ACMEChallengeSolverHTTP01GatewayHTTPRoute{
								ParentRefs: []gwapi.ParentReference{
									{
										Name: "blah",
									},
								},
							},
						},
					},
				},
			},
		},
		"acme solver with invalid http01 gateway config": {
			spec: &cmacme.ACMEIssuer{
				Email:      "valid-email",
				Server:     "valid-server",
				PrivateKey: validSecretKeyRef,
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							GatewayHTTPRoute: &cmacme.ACMEChallengeSolverHTTP01GatewayHTTPRoute{},
						},
					},
				},
			},
			errs: []*field.Error{
				field.Required(
					fldPath.Child("solvers").Index(0).Child("http01", "gateway").Child("parentRefs"),
					"at least 1 parentRef is required",
				),
			},
		},
		"acme solver with multiple http01 solver configs": {
			spec: &cmacme.ACMEIssuer{
				Email:      "valid-email",
				Server:     "valid-server",
				PrivateKey: validSecretKeyRef,
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
							GatewayHTTPRoute: &cmacme.ACMEChallengeSolverHTTP01GatewayHTTPRoute{
								Labels: map[string]string{
									"a": "b",
								},
								ParentRefs: []gwapi.ParentReference{
									{
										Name: "blah",
									},
								},
							},
						},
					},
				},
			},
			errs: []*field.Error{
				field.Required(
					fldPath.Child("solvers").Index(0).Child("http01"),
					"only 1 HTTP01 solver type may be configured",
				),
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
			errs, warnings := ValidateACMEIssuerConfig(s.spec, fldPath)
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
			assert.Equal(t, s.warnings, warnings)
		})
	}
}

func TestValidateIssuerSpec(t *testing.T) {
	fldPath := (*field.Path)(nil)

	scenarios := map[string]struct {
		spec     *cmapi.IssuerSpec
		errs     field.ErrorList
		warnings []string
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
		"valid IssuingCertificateURLs": {
			spec: &cmapi.IssuerSpec{
				IssuerConfig: cmapi.IssuerConfig{
					CA: &cmapi.CAIssuer{
						SecretName:             "valid",
						IssuingCertificateURLs: []string{"http://ca.example.com/ca.crt"},
					},
				},
			},
			errs: []*field.Error{},
		},
		"invalid IssuingCertificateURLs": {
			spec: &cmapi.IssuerSpec{
				IssuerConfig: cmapi.IssuerConfig{
					CA: &cmapi.CAIssuer{
						SecretName:             "valid",
						IssuingCertificateURLs: []string{""},
					},
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("ca", "issuingCertificateURLs").Index(0), "", `must be a valid URL`),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			gotErrs, warnings := ValidateIssuerSpec(s.spec, fldPath)
			assert.Equal(t, s.errs, gotErrs)
			assert.Equal(t, s.warnings, warnings)
		})
	}
}

func TestValidateACMEIssuerHTTP01Config(t *testing.T) {
	fldPath := (*field.Path)(nil)

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
				Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{Class: ptr.To("abc")},
			},
		},
		"ingressClassName field specified": {
			cfg: &cmacme.ACMEChallengeSolverHTTP01{
				Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{IngressClassName: ptr.To("abc")},
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
		"all three fields specified": {
			cfg: &cmacme.ACMEChallengeSolverHTTP01{
				Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
					Name:             "abc",
					Class:            ptr.To("abc"),
					IngressClassName: ptr.To("abc"),
				},
			},
			errs: []*field.Error{
				field.Forbidden(fldPath.Child("ingress"), "only one of 'ingressClassName', 'name' or 'class' should be specified"),
			},
		},
		"ingressClassName is invalid": {
			cfg: &cmacme.ACMEChallengeSolverHTTP01{
				Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
					IngressClassName: ptr.To("azure/application-gateway"),
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("ingress", "ingressClassName"), "azure/application-gateway", `must be a valid IngressClass name: a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')`),
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
		"empty route53 field should be valid because ambient credentials and region may be used instead": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{},
			},
			errs: []*field.Error{},
		},
		"both route53 accessKeyID and accessKeyIDSecretRef specified": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
					Region:            "valid",
					AccessKeyID:       "valid",
					SecretAccessKeyID: &validSecretKeyRef,
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("route53"), "accessKeyID and accessKeyIDSecretRef cannot both be specified"),
			},
		},
		"route53 accessKeyIDSecretRef missing name": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
					Region: "valid",
					SecretAccessKeyID: &cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{},
						Key:                  "key",
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("route53", "accessKeyIDSecretRef", "name"), "secret name is required"),
			},
		},
		"route53 accessKeyIDSecretRef missing key": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
					Region: "valid",
					SecretAccessKeyID: &cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{Name: "name"},
						Key:                  "",
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("route53", "accessKeyIDSecretRef", "key"), "secret key is required"),
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
		"invalid azuredns clientID used with managedIdentity": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
					ClientID: "some-client-id",
					ManagedIdentity: &cmacme.AzureManagedIdentity{
						ClientID: "test",
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("azureDNS", "clientSecretSecretRef"), ""),
				field.Required(fldPath.Child("azureDNS", "tenantID"), ""),
				field.Forbidden(fldPath.Child("azureDNS", "managedIdentity"), "managed identity can not be used at the same time as clientID, clientSecretSecretRef or tenantID"),
				field.Required(fldPath.Child("azureDNS", "subscriptionID"), ""),
				field.Required(fldPath.Child("azureDNS", "resourceGroupName"), ""),
			},
		},
		"invalid azuredns tenantID used with managedIdentity": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
					TenantID: "some-tenant-id",
					ManagedIdentity: &cmacme.AzureManagedIdentity{
						ClientID: "test",
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("azureDNS", "clientID"), ""),
				field.Required(fldPath.Child("azureDNS", "clientSecretSecretRef"), ""),
				field.Forbidden(fldPath.Child("azureDNS", "managedIdentity"), "managed identity can not be used at the same time as clientID, clientSecretSecretRef or tenantID"),
				field.Required(fldPath.Child("azureDNS", "subscriptionID"), ""),
				field.Required(fldPath.Child("azureDNS", "resourceGroupName"), ""),
			},
		},
		"invalid azuredns clientSecret used with managedIdentity": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
					ClientSecret: &cmmeta.SecretKeySelector{
						Key: "some-key",
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: "some-secret-name",
						},
					},
					ManagedIdentity: &cmacme.AzureManagedIdentity{
						ClientID: "test",
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("azureDNS", "clientID"), ""),
				field.Required(fldPath.Child("azureDNS", "tenantID"), ""),
				field.Forbidden(fldPath.Child("azureDNS", "managedIdentity"), "managed identity can not be used at the same time as clientID, clientSecretSecretRef or tenantID"),
				field.Required(fldPath.Child("azureDNS", "subscriptionID"), ""),
				field.Required(fldPath.Child("azureDNS", "resourceGroupName"), ""),
			},
		},
		"valid azuredns with managedIdentity": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
					SubscriptionID:    "test",
					ResourceGroupName: "test",
				},
			},
			errs: []*field.Error{},
		},
		"valid azuredns with managedIdentity with clientID": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
					SubscriptionID:    "test",
					ResourceGroupName: "test",
					ManagedIdentity: &cmacme.AzureManagedIdentity{
						ClientID: "test",
					},
				},
			},
			errs: []*field.Error{},
		},
		"valid azuredns with managedIdentity with resourceID": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
					SubscriptionID:    "test",
					ResourceGroupName: "test",
					ManagedIdentity: &cmacme.AzureManagedIdentity{
						ResourceID: "test",
					},
				},
			},
			errs: []*field.Error{},
		},
		"invalid azuredns managedIdentity with both cliendID and resourceID": {
			cfg: &cmacme.ACMEChallengeSolverDNS01{
				AzureDNS: &cmacme.ACMEIssuerDNS01ProviderAzureDNS{
					SubscriptionID:    "test",
					ResourceGroupName: "test",
					ManagedIdentity: &cmacme.AzureManagedIdentity{
						ClientID:   "test",
						ResourceID: "test",
					},
				},
			},
			errs: []*field.Error{
				field.Forbidden(fldPath.Child("azureDNS", "managedIdentity"), "managedIdentityClientID and managedIdentityResourceID cannot both be specified"),
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
	fldPath := (*field.Path)(nil)

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
	caBundle := unitcrypto.MustCreateCryptoBundle(t,
		&pubcmapi.Certificate{Spec: pubcmapi.CertificateSpec{CommonName: "test"}},
		clock.RealClock{},
	).CertBytes
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
		"venafi TPP issuer defines both caBundle and caBundleSecretRef": {
			cfg: &cmapi.VenafiTPP{
				URL:      "https://tpp.example.com/vedsdk",
				CABundle: caBundle,
				CABundleSecretRef: &cmmeta.SecretKeySelector{
					Key: "ca.crt",
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: "test-secret",
					},
				},
			},
			errs: []*field.Error{
				field.Forbidden(fldPath, "may not specify more than one of caBundle/caBundleSecretRef as TPP CA Bundle"),
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

func TestValidateIssuer(t *testing.T) {
	scenarios := map[string]struct {
		cfg       *cmapi.Issuer
		a         *admissionv1.AdmissionRequest
		expectedE []*field.Error
		expectedW []string
	}{}

	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			gotE, gotW := ValidateIssuer(s.a, s.cfg)
			if len(gotE) != len(s.expectedE) {
				t.Fatalf("Expected errors %v but got %v", s.expectedE, gotE)
			}
			if len(gotW) != len(s.expectedW) {
				t.Fatalf("Expected warnings %v but got %v", s.expectedE, gotE)
			}
			for i, e := range gotE {
				expectedErr := s.expectedE[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected warnings %v but got %v", expectedErr, e)
				}
			}
			for i, w := range gotW {
				expectedWarning := s.expectedW[i]
				if w != expectedWarning {
					t.Errorf("Expected warning %q but got %q", expectedWarning, w)
				}
			}
		})
	}
}

func TestUpdateValidateIssuer(t *testing.T) {
	baseIssuerConfig := cmapi.IssuerSpec{
		IssuerConfig: cmapi.IssuerConfig{
			SelfSigned: &cmapi.SelfSignedIssuer{},
		}}
	baseIssuer := cmapi.Issuer{
		Spec: baseIssuerConfig,
	}
	scenarios := map[string]struct {
		iss       *cmapi.Issuer
		a         *admissionv1.AdmissionRequest
		expectedE []*field.Error
		expectedW []string
	}{}

	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			gotE, gotW := ValidateUpdateIssuer(s.a, &baseIssuer, s.iss)
			if len(gotE) != len(s.expectedE) {
				t.Fatalf("Expected errors %v but got %v", s.expectedE, gotE)
			}
			if len(gotW) != len(s.expectedW) {
				t.Fatalf("Expected warnings %v but got %v", s.expectedE, gotE)
			}
			for i, e := range gotE {
				expectedErr := s.expectedE[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected warnings %v but got %v", expectedErr, e)
				}
			}
			for i, w := range gotW {
				expectedWarning := s.expectedW[i]
				if w != expectedWarning {
					t.Errorf("Expected warning %q but got %q", expectedWarning, w)
				}
			}
		})
	}
}
