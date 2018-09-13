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

package validation

import (
	"reflect"
	"testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/util/generate"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	defaultTestIssuerName = "test-issuer"
	defaultTestCrtName    = "test-crt"
	defaultTestNamespace  = "default"
)

func TestValidateCertificateForIssuer(t *testing.T) {
	fldPath := field.NewPath("spec")

	scenarios := map[string]struct {
		crt    *v1alpha1.Certificate
		issuer *v1alpha1.Issuer
		errs   []*field.Error
	}{
		"valid basic certificate": {
			crt: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					IssuerRef: validIssuerRef,
					ACME: &v1alpha1.ACMECertificateConfig{
						Config: []v1alpha1.DomainSolverConfig{
							{
								Domains: []string{"example.com"},
								SolverConfig: v1alpha1.SolverConfig{
									HTTP01: &v1alpha1.HTTP01SolverConfig{},
								},
							},
						},
					},
				},
			},

			issuer: generate.Issuer(generate.IssuerConfig{
				Name:      defaultTestIssuerName,
				Namespace: defaultTestNamespace,
			}),
		},
		"certificate with invalid keyAlgorithm": {
			crt: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					KeyAlgorithm: v1alpha1.KeyAlgorithm("blah"),
					IssuerRef:    validIssuerRef,
					ACME: &v1alpha1.ACMECertificateConfig{
						Config: []v1alpha1.DomainSolverConfig{
							{
								Domains: []string{"example.com"},
								SolverConfig: v1alpha1.SolverConfig{
									HTTP01: &v1alpha1.HTTP01SolverConfig{},
								},
							},
						},
					},
				},
			},
			issuer: generate.Issuer(generate.IssuerConfig{
				Name:      defaultTestIssuerName,
				Namespace: defaultTestNamespace,
			}),
			errs: []*field.Error{
				field.Invalid(fldPath.Child("keyAlgorithm"), v1alpha1.KeyAlgorithm("blah"), "ACME key algorithm must be RSA"),
			},
		},
		"certificate with correct keyAlgorithm for ACME": {
			crt: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					KeyAlgorithm: v1alpha1.RSAKeyAlgorithm,
					IssuerRef:    validIssuerRef,
					ACME: &v1alpha1.ACMECertificateConfig{
						Config: []v1alpha1.DomainSolverConfig{
							{
								Domains: []string{"example.com"},
								SolverConfig: v1alpha1.SolverConfig{
									HTTP01: &v1alpha1.HTTP01SolverConfig{},
								},
							},
						},
					},
				},
			},
			issuer: generate.Issuer(generate.IssuerConfig{
				Name:      defaultTestIssuerName,
				Namespace: defaultTestNamespace,
			}),
		},
		"certificate with incorrect keyAlgorithm for ACME": {
			crt: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					KeyAlgorithm: v1alpha1.ECDSAKeyAlgorithm,
					IssuerRef:    validIssuerRef,
					ACME: &v1alpha1.ACMECertificateConfig{
						Config: []v1alpha1.DomainSolverConfig{
							{
								Domains: []string{"example.com"},
								SolverConfig: v1alpha1.SolverConfig{
									HTTP01: &v1alpha1.HTTP01SolverConfig{},
								},
							},
						},
					},
				},
			},
			issuer: generate.Issuer(generate.IssuerConfig{
				Name:      defaultTestIssuerName,
				Namespace: defaultTestNamespace,
			}),
			errs: []*field.Error{
				field.Invalid(fldPath.Child("keyAlgorithm"), v1alpha1.ECDSAKeyAlgorithm, "ACME key algorithm must be RSA"),
			},
		},
		"certificate with unspecified issuer type": {
			crt: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					KeyAlgorithm: v1alpha1.ECDSAKeyAlgorithm,
					IssuerRef:    validIssuerRef,
					ACME: &v1alpha1.ACMECertificateConfig{
						Config: []v1alpha1.DomainSolverConfig{
							{
								Domains: []string{"example.com"},
								SolverConfig: v1alpha1.SolverConfig{
									HTTP01: &v1alpha1.HTTP01SolverConfig{},
								},
							},
						},
					},
				},
			},
			issuer: &v1alpha1.Issuer{},
			errs: []*field.Error{
				field.Invalid(fldPath, "no issuer specified for Issuer '/'", "no issuer specified for Issuer '/'"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateCertificateForIssuer(s.crt, s.issuer)
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
