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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

const (
	defaultTestIssuerName = "test-issuer"
	defaultTestCrtName    = "test-crt"
	defaultTestNamespace  = gen.DefaultTestNamespace
)

func TestValidateCertificateForIssuer(t *testing.T) {
	fldPath := field.NewPath("spec")

	scenarios := map[string]struct {
		crt    *v1alpha2.Certificate
		issuer *v1alpha2.Issuer
		errs   []*field.Error
	}{
		"valid basic certificate": {
			crt: &v1alpha2.Certificate{
				Spec: v1alpha2.CertificateSpec{
					IssuerRef: validIssuerRef,
				},
			},
			issuer: gen.Issuer(defaultTestIssuerName, gen.SetIssuerACME(v1alpha2.ACMEIssuer{})),
		},
		"certificate with RSA keyAlgorithm for ACME": {
			crt: &v1alpha2.Certificate{
				Spec: v1alpha2.CertificateSpec{
					KeyAlgorithm: v1alpha2.RSAKeyAlgorithm,
					IssuerRef:    validIssuerRef,
				},
			},
			issuer: gen.Issuer(defaultTestIssuerName, gen.SetIssuerACME(v1alpha2.ACMEIssuer{})),
		},
		"certificate with ECDSA keyAlgorithm for ACME": {
			crt: &v1alpha2.Certificate{
				Spec: v1alpha2.CertificateSpec{
					KeyAlgorithm: v1alpha2.ECDSAKeyAlgorithm,
					IssuerRef:    validIssuerRef,
				},
			},
			issuer: gen.Issuer(defaultTestIssuerName, gen.SetIssuerACME(v1alpha2.ACMEIssuer{})),
		},
		"acme certificate with organization set": {
			crt: &v1alpha2.Certificate{
				Spec: v1alpha2.CertificateSpec{
					Organization: []string{"shouldfailorg"},
					IssuerRef:    validIssuerRef,
				},
			},
			issuer: gen.Issuer(defaultTestIssuerName, gen.SetIssuerACME(v1alpha2.ACMEIssuer{})),
			errs: []*field.Error{
				field.Invalid(fldPath.Child("organization"), []string{"shouldfailorg"}, "ACME does not support setting the organization name"),
			},
		},
		"acme certificate with duration set": {
			crt: &v1alpha2.Certificate{
				Spec: v1alpha2.CertificateSpec{
					Duration:  &metav1.Duration{Duration: time.Minute * 60},
					IssuerRef: validIssuerRef,
				},
			},
			issuer: gen.Issuer(defaultTestIssuerName, gen.SetIssuerACME(v1alpha2.ACMEIssuer{})),
			errs: []*field.Error{
				field.Invalid(fldPath.Child("duration"), &metav1.Duration{Duration: time.Minute * 60}, "ACME does not support certificate durations"),
			},
		},
		"acme certificate with ipAddresses set": {
			crt: &v1alpha2.Certificate{
				Spec: v1alpha2.CertificateSpec{
					IPAddresses: []string{"127.0.0.1"},
					IssuerRef:   validIssuerRef,
				},
			},
			issuer: gen.Issuer(defaultTestIssuerName, gen.SetIssuerACME(v1alpha2.ACMEIssuer{})),
			errs: []*field.Error{
				field.Invalid(fldPath.Child("ipAddresses"), []string{"127.0.0.1"}, "ACME does not support certificate ip addresses"),
			},
		},
		"acme certificate with renewBefore set": {
			crt: &v1alpha2.Certificate{
				Spec: v1alpha2.CertificateSpec{
					RenewBefore: &metav1.Duration{Duration: time.Minute * 60},
					IssuerRef:   validIssuerRef,
				},
			},
			issuer: gen.Issuer(defaultTestIssuerName, gen.SetIssuerACME(v1alpha2.ACMEIssuer{})),
			errs:   []*field.Error{},
		},
		"certificate with unspecified issuer type": {
			crt: &v1alpha2.Certificate{
				Spec: v1alpha2.CertificateSpec{
					KeyAlgorithm: v1alpha2.ECDSAKeyAlgorithm,
					IssuerRef:    validIssuerRef,
				},
			},
			issuer: &v1alpha2.Issuer{},
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
