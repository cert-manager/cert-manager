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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmacme "github.com/cert-manager/cert-manager/internal/apis/acme"
	cmapi "github.com/cert-manager/cert-manager/internal/apis/certmanager"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

const (
	defaultTestIssuerName = "test-issuer"
	defaultTestNamespace  = gen.DefaultTestNamespace
)

func TestValidateCertificateForIssuer(t *testing.T) {
	fldPath := field.NewPath("spec")
	acmeIssuer := &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultTestIssuerName,
			Namespace: defaultTestNamespace,
		},
		Spec: cmapi.IssuerSpec{
			IssuerConfig: cmapi.IssuerConfig{
				ACME: &cmacme.ACMEIssuer{},
			},
		},
	}
	scenarios := map[string]struct {
		crt    *cmapi.Certificate
		issuer *cmapi.Issuer
		errs   []*field.Error
	}{
		"valid basic certificate": {
			crt: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					IssuerRef: validIssuerRef,
				},
			},
			issuer: acmeIssuer,
		},
		"certificate with RSA keyAlgorithm for ACME": {
			crt: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.RSAKeyAlgorithm,
					},
					IssuerRef: validIssuerRef,
				},
			},
			issuer: acmeIssuer,
		},
		"certificate with ECDSA keyAlgorithm for ACME": {
			crt: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.ECDSAKeyAlgorithm,
					},
					IssuerRef: validIssuerRef,
				},
			},
			issuer: acmeIssuer,
		},
		"acme certificate with organization set": {
			crt: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					Subject: &cmapi.X509Subject{
						Organizations: []string{"shouldfailorg"},
					},
					IssuerRef: validIssuerRef,
				},
			},
			issuer: acmeIssuer,
			errs: []*field.Error{
				field.Invalid(fldPath.Child("subject", "organizations"), []string{"shouldfailorg"}, "ACME does not support setting the organization name"),
			},
		},
		"acme certificate with duration set": {
			crt: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					Duration:  &metav1.Duration{Duration: time.Minute * 60},
					IssuerRef: validIssuerRef,
				},
			},
			issuer: acmeIssuer,
			errs: []*field.Error{
				field.Invalid(fldPath.Child("duration"), &metav1.Duration{Duration: time.Minute * 60}, "ACME does not support certificate durations"),
			},
		},
		"acme certificate with ipAddresses set": {
			crt: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					IPAddresses: []string{"127.0.0.1"},
					IssuerRef:   validIssuerRef,
				},
			},
			issuer: acmeIssuer,
			errs: []*field.Error{
				field.Invalid(fldPath.Child("ipAddresses"), []string{"127.0.0.1"}, "ACME does not support certificate ip addresses"),
			},
		},
		"acme certificate with renewBefore set": {
			crt: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					RenewBefore: &metav1.Duration{Duration: time.Minute * 60},
					IssuerRef:   validIssuerRef,
				},
			},
			issuer: acmeIssuer,
			errs:   []*field.Error{},
		},
		"certificate with unspecified issuer type": {
			crt: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.ECDSAKeyAlgorithm,
					},
					IssuerRef: validIssuerRef,
				},
			},
			issuer: &cmapi.Issuer{},
			errs: []*field.Error{
				field.Invalid(fldPath, "", "no issuer specified for Issuer '/'"),
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
