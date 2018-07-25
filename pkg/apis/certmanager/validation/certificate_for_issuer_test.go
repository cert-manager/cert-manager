package validation

import (
	"reflect"
	"testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestValidateCertificateForACMEIssuer(t *testing.T) {
	fldPath := field.NewPath("spec")
	scenarios := map[string]struct {
		spec   *v1alpha1.CertificateSpec
		issuer *v1alpha1.IssuerSpec
		errs   []*field.Error
	}{
		"valid basic certificate": {
			spec: &v1alpha1.CertificateSpec{
				CommonName: "testcn",
				SecretName: "abc",
				IssuerRef:  validIssuerRef,
			},
			issuer: &v1alpha1.IssuerSpec{},
		},
		"certificate with invalid keyAlgorithm": {
			spec: &v1alpha1.CertificateSpec{
				CommonName:   "testcn",
				SecretName:   "abc",
				IssuerRef:    validIssuerRef,
				KeyAlgorithm: v1alpha1.KeyAlgorithm("blah"),
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("keyAlgorithm"), v1alpha1.KeyAlgorithm("blah"), "ACME key algorithm must be RSA"),
			},
		},
		"certificate with correct keyAlgorithm for ACME": {
			spec: &v1alpha1.CertificateSpec{
				CommonName:   "testcn",
				SecretName:   "abc",
				IssuerRef:    validIssuerRef,
				KeyAlgorithm: v1alpha1.RSAKeyAlgorithm,
			},
		},
		"certificate with incorrect keyAlgorithm for ACME": {
			spec: &v1alpha1.CertificateSpec{
				CommonName:   "testcn",
				SecretName:   "abc",
				IssuerRef:    validIssuerRef,
				KeyAlgorithm: v1alpha1.ECDSAKeyAlgorithm,
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("keyAlgorithm"), v1alpha1.ECDSAKeyAlgorithm, "ACME key algorithm must be RSA"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			path := field.NewPath("spec")
			errs := ValidateCertificateForACMEIssuer(s.spec, s.issuer, path)
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
