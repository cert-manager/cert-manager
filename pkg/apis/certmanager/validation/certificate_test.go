package validation

import (
	"reflect"
	"testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

var (
	validIssuerRef = v1alpha1.ObjectReference{
		Name: "name",
		Kind: "ClusterIssuer",
	}
)

func strPtr(s string) *string {
	return &s
}

func TestValidateCertificate(t *testing.T) {
	fldPath := field.NewPath("spec")
	scenarios := map[string]struct {
		cfg  *v1alpha1.Certificate
		errs []*field.Error
	}{
		"valid basic certificate": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
		},
		"valid with blank issuerRef kind": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef: v1alpha1.ObjectReference{
						Name: "valid",
					},
				},
			},
		},
		"valid with 'Issuer' issuerRef kind": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef: v1alpha1.ObjectReference{
						Name: "valid",
						Kind: "Issuer",
					},
				},
			},
		},
		"invalid issuerRef kind": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef: v1alpha1.ObjectReference{
						Name: "valid",
						Kind: "invalid",
					},
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("issuerRef", "kind"), "invalid", "must be one of Issuer or ClusterIssuer"),
			},
		},
		"certificate missing secretName": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName: "testcn",
					IssuerRef:  validIssuerRef,
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("secretName"), "must be specified"),
			},
		},
		"certificate with no domains": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("dnsNames"), "at least one dnsName is required if commonName is not set"),
			},
		},
		"certificate with no issuerRef": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("issuerRef", "name"), "must be specified"),
			},
		},
		"valid certificate with only dnsNames": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					DNSNames:   []string{"validdnsname"},
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
		},
		"valid acme certificate": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					DNSNames:   []string{"validdnsname"},
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					ACME: &v1alpha1.ACMECertificateConfig{
						Config: []v1alpha1.ACMECertificateDomainConfig{
							{
								Domains: []string{"validdnsname"},
								ACMESolverConfig: v1alpha1.ACMESolverConfig{
									HTTP01: &v1alpha1.ACMECertificateHTTP01Config{},
								},
							},
						},
					},
				},
			},
		},
		"acme certificate with missing solver configuration for dns name": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					DNSNames:   []string{"validdnsname", "anotherdnsname"},
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					ACME: &v1alpha1.ACMECertificateConfig{
						Config: []v1alpha1.ACMECertificateDomainConfig{
							{
								Domains: []string{"validdnsname"},
								ACMESolverConfig: v1alpha1.ACMESolverConfig{
									HTTP01: &v1alpha1.ACMECertificateHTTP01Config{},
								},
							},
						},
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("acme", "config"), "no ACME solver configuration specified for domain \"anotherdnsname\""),
			},
		},
		"acme certificate with missing solver configuration for common name": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName: "commonname",
					DNSNames:   []string{"validdnsname"},
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					ACME: &v1alpha1.ACMECertificateConfig{
						Config: []v1alpha1.ACMECertificateDomainConfig{
							{
								Domains: []string{"validdnsname"},
								ACMESolverConfig: v1alpha1.ACMESolverConfig{
									HTTP01: &v1alpha1.ACMECertificateHTTP01Config{},
								},
							},
						},
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("acme", "config"), "no ACME solver configuration specified for domain \"commonname\""),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateCertificate(s.cfg)
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
func TestValidateACMECertificateConfig(t *testing.T) {
	fldPath := field.NewPath("")
	scenarios := map[string]struct {
		isExpectedFailure bool
		cfg               *v1alpha1.ACMECertificateConfig
		errs              []*field.Error
	}{
		"valid acme configuration": {
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.ACMECertificateDomainConfig{
					{
						Domains: []string{"abc.xyz"},
						ACMESolverConfig: v1alpha1.ACMESolverConfig{
							HTTP01: &v1alpha1.ACMECertificateHTTP01Config{},
						},
					},
				},
			},
		},
		"acme configuration missing for domain": {
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.ACMECertificateDomainConfig{
					{
						Domains:          []string{"abc.xyz"},
						ACMESolverConfig: v1alpha1.ACMESolverConfig{},
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("config").Index(0), "at least one solver must be configured"),
			},
		},
		"acme dns01 configuration missing provider name": {
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.ACMECertificateDomainConfig{
					{
						Domains: []string{"abc.xyz"},
						ACMESolverConfig: v1alpha1.ACMESolverConfig{
							DNS01: &v1alpha1.ACMECertificateDNS01Config{},
						},
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("config").Index(0).Child("dns01", "provider"), "provider name must be set"),
			},
		},
		"valid acme dns01 configuration": {
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.ACMECertificateDomainConfig{
					{
						Domains: []string{"abc.xyz"},
						ACMESolverConfig: v1alpha1.ACMESolverConfig{
							DNS01: &v1alpha1.ACMECertificateDNS01Config{
								Provider: "abc",
							},
						},
					},
				},
			},
			errs: []*field.Error{},
		},
		"no domains specified": {
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.ACMECertificateDomainConfig{
					{
						Domains: []string{},
						ACMESolverConfig: v1alpha1.ACMESolverConfig{
							HTTP01: &v1alpha1.ACMECertificateHTTP01Config{},
						},
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("config").Index(0).Child("domains"), "at least one domain must be specified"),
			},
		},
		"multiple solvers configured": {
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.ACMECertificateDomainConfig{
					{
						Domains: []string{"abc.xyz"},
						ACMESolverConfig: v1alpha1.ACMESolverConfig{
							HTTP01: &v1alpha1.ACMECertificateHTTP01Config{},
							DNS01: &v1alpha1.ACMECertificateDNS01Config{
								Provider: "abc",
							},
						},
					},
				},
			},
			errs: []*field.Error{
				field.Forbidden(fldPath.Child("config").Index(0).Child("http01"), "may not specify more than one solver type"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateACMECertificateConfig(s.cfg, fldPath)
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

func TestValidateACMECertificateHTTP01Config(t *testing.T) {
	fldPath := field.NewPath("")
	scenarios := map[string]struct {
		isExpectedFailure bool
		cfg               *v1alpha1.ACMECertificateHTTP01Config
		errs              []*field.Error
	}{
		"ingress field specified": {
			cfg: &v1alpha1.ACMECertificateHTTP01Config{
				Ingress: "abc",
			},
		},
		"ingress class field specified": {
			cfg: &v1alpha1.ACMECertificateHTTP01Config{
				IngressClass: strPtr("abc"),
			},
		},
		"neither field specified": {
			cfg:  &v1alpha1.ACMECertificateHTTP01Config{},
			errs: []*field.Error{},
		},
		"both fields specified": {
			cfg: &v1alpha1.ACMECertificateHTTP01Config{
				Ingress:      "abc",
				IngressClass: strPtr("abc"),
			},
			errs: []*field.Error{
				field.Forbidden(fldPath, "only one of 'ingress' and 'ingressClass' should be specified"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateACMECertificateHTTP01Config(s.cfg, fldPath)
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
