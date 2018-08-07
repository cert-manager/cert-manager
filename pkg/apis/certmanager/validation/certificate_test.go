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
						Config: []v1alpha1.DomainSolverConfig{
							{
								Domains: []string{"validdnsname"},
								SolverConfig: v1alpha1.SolverConfig{
									HTTP01: &v1alpha1.HTTP01SolverConfig{},
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
						Config: []v1alpha1.DomainSolverConfig{
							{
								Domains: []string{"validdnsname"},
								SolverConfig: v1alpha1.SolverConfig{
									HTTP01: &v1alpha1.HTTP01SolverConfig{},
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
						Config: []v1alpha1.DomainSolverConfig{
							{
								Domains: []string{"validdnsname"},
								SolverConfig: v1alpha1.SolverConfig{
									HTTP01: &v1alpha1.HTTP01SolverConfig{},
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
		"valid certificate with rsa keyAlgorithm specified and no keySize": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: v1alpha1.RSAKeyAlgorithm,
				},
			},
		},
		"valid certificate with rsa keyAlgorithm specified with keySize 2048": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: v1alpha1.RSAKeyAlgorithm,
					KeySize:      2048,
				},
			},
		},
		"valid certificate with rsa keyAlgorithm specified with keySize 4096": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: v1alpha1.RSAKeyAlgorithm,
					KeySize:      4096,
				},
			},
		},
		"valid certificate with rsa keyAlgorithm specified with keySize 8192": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: v1alpha1.RSAKeyAlgorithm,
					KeySize:      8192,
				},
			},
		},
		"valid certificate with ecdsa keyAlgorithm specified and no keySize": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: v1alpha1.ECDSAKeyAlgorithm,
				},
			},
		},
		"valid certificate with ecdsa keyAlgorithm specified with keySize 256": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: v1alpha1.ECDSAKeyAlgorithm,
					KeySize:      256,
				},
			},
		},
		"valid certificate with ecdsa keyAlgorithm specified with keySize 384": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: v1alpha1.ECDSAKeyAlgorithm,
					KeySize:      384,
				},
			},
		},
		"valid certificate with ecdsa keyAlgorithm specified with keySize 521": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: v1alpha1.ECDSAKeyAlgorithm,
					KeySize:      521,
				},
			},
		},
		"valid certificate with keyAlgorithm not specified and keySize specified": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					KeySize:    2048,
				},
			},
		},
		"certificate with keysize less than zero": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					KeySize:    -99,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("keySize"), -99, "cannot be less than zero"),
			},
		},
		"certificate with rsa keyAlgorithm specified and invalid keysize 1024": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: v1alpha1.RSAKeyAlgorithm,
					KeySize:      1024,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("keySize"), 1024, "must be between 2048 & 8192 for rsa keyAlgorithm"),
			},
		},
		"certificate with rsa keyAlgorithm specified and invalid keysize 8196": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: v1alpha1.RSAKeyAlgorithm,
					KeySize:      8196,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("keySize"), 8196, "must be between 2048 & 8192 for rsa keyAlgorithm"),
			},
		},
		"certificate with ecdsa keyAlgorithm specified and invalid keysize": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: v1alpha1.ECDSAKeyAlgorithm,
					KeySize:      100,
				},
			},
			errs: []*field.Error{
				field.NotSupported(fldPath.Child("keySize"), 100, []string{"256", "384", "521"}),
			},
		},
		"certificate with invalid keyAlgorithm": {
			cfg: &v1alpha1.Certificate{
				Spec: v1alpha1.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: v1alpha1.KeyAlgorithm("blah"),
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("keyAlgorithm"), v1alpha1.KeyAlgorithm("blah"), "must be either empty or one of rsa or ecdsa"),
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
				Config: []v1alpha1.DomainSolverConfig{
					{
						Domains: []string{"abc.xyz"},
						SolverConfig: v1alpha1.SolverConfig{
							HTTP01: &v1alpha1.HTTP01SolverConfig{},
						},
					},
				},
			},
		},
		"acme configuration missing for domain": {
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.DomainSolverConfig{
					{
						Domains:      []string{"abc.xyz"},
						SolverConfig: v1alpha1.SolverConfig{},
					},
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("config").Index(0), "at least one solver must be configured"),
			},
		},
		"acme dns01 configuration missing provider name": {
			cfg: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.DomainSolverConfig{
					{
						Domains: []string{"abc.xyz"},
						SolverConfig: v1alpha1.SolverConfig{
							DNS01: &v1alpha1.DNS01SolverConfig{},
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
				Config: []v1alpha1.DomainSolverConfig{
					{
						Domains: []string{"abc.xyz"},
						SolverConfig: v1alpha1.SolverConfig{
							DNS01: &v1alpha1.DNS01SolverConfig{
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
				Config: []v1alpha1.DomainSolverConfig{
					{
						Domains: []string{},
						SolverConfig: v1alpha1.SolverConfig{
							HTTP01: &v1alpha1.HTTP01SolverConfig{},
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
				Config: []v1alpha1.DomainSolverConfig{
					{
						Domains: []string{"abc.xyz"},
						SolverConfig: v1alpha1.SolverConfig{
							HTTP01: &v1alpha1.HTTP01SolverConfig{},
							DNS01: &v1alpha1.DNS01SolverConfig{
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

func TestValidateHTTP01SolverConfig(t *testing.T) {
	fldPath := field.NewPath("")
	scenarios := map[string]struct {
		isExpectedFailure bool
		cfg               *v1alpha1.HTTP01SolverConfig
		errs              []*field.Error
	}{
		"ingress field specified": {
			cfg: &v1alpha1.HTTP01SolverConfig{
				Ingress: "abc",
			},
		},
		"ingress class field specified": {
			cfg: &v1alpha1.HTTP01SolverConfig{
				IngressClass: strPtr("abc"),
			},
		},
		"neither field specified": {
			cfg:  &v1alpha1.HTTP01SolverConfig{},
			errs: []*field.Error{},
		},
		"both fields specified": {
			cfg: &v1alpha1.HTTP01SolverConfig{
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
			errs := ValidateHTTP01SolverConfig(s.cfg, fldPath)
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
