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
	"time"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/util/generate"
	"k8s.io/apimachinery/pkg/util/validation/field"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		"certificate with RSA keyAlgorithm for ACME": {
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
		"certificate with ECDSA keyAlgorithm for ACME": {
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
		},
		"acme certificate with organization set": {
			crt: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					Organization: []string{"shouldfailorg"},
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
				field.Invalid(fldPath.Child("organization"), []string{"shouldfailorg"}, "ACME does not support setting the organization name"),
			},
		},
		"acme certificate with duration set": {
			crt: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					Duration:  &metav1.Duration{Duration: time.Minute * 60},
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
			errs: []*field.Error{
				field.Invalid(fldPath.Child("duration"), &metav1.Duration{Duration: time.Minute * 60}, "ACME does not support certificate durations"),
			},
		},
		"acme certificate with ipAddresses set": {
			crt: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					IPAddresses: []string{"127.0.0.1"},
					IssuerRef:   validIssuerRef,
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
				field.Invalid(fldPath.Child("ipAddresses"), []string{"127.0.0.1"}, "ACME does not support certificate ip addresses"),
			},
		},
		"acme certificate with renewBefore set": {
			crt: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					RenewBefore: &metav1.Duration{Duration: time.Minute * 60},
					IssuerRef:   validIssuerRef,
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
			errs: []*field.Error{},
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
