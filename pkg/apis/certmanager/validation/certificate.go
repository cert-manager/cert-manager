package validation

import (
	"fmt"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// Validation functions for cert-manager v1alpha1 Certificate types

func ValidateCertificate(crt *v1alpha1.Certificate) field.ErrorList {
	allErrs := ValidateCertificateSpec(&crt.Spec, field.NewPath("spec"))
	return allErrs
}

func ValidateCertificateSpec(crt *v1alpha1.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if crt.SecretName == "" {
		el = append(el, field.Required(fldPath.Child("secretName"), "must be specified"))
	}
	issuerRefPath := fldPath.Child("issuerRef")
	if crt.IssuerRef.Name == "" {
		el = append(el, field.Required(issuerRefPath.Child("name"), "must be specified"))
	}
	switch crt.IssuerRef.Kind {
	case "":
		// For now we disable this check in order to support older versions where
		// defaulting doesn't occur
		glog.Infof("Certificate does not set issuerRef.kind - " +
			"in future versions of cert-manager, this will be a hard failure.")
		// el = append(el, field.Required(issuerRefPath.Child("kind"), "must be specified"))
	case "Issuer", "ClusterIssuer":
	default:
		el = append(el, field.Invalid(issuerRefPath.Child("kind"), crt.IssuerRef.Kind, "must be one of Issuer or ClusterIssuer"))
	}
	if len(crt.CommonName) == 0 && len(crt.DNSNames) == 0 {
		el = append(el, field.Required(fldPath.Child("dnsNames"), "at least one dnsName is required if commonName is not set"))
	}
	if crt.ACME != nil {
		el = append(el, validateACMEConfigForAllDNSNames(crt, fldPath)...)
		el = append(el, ValidateACMECertificateConfig(crt.ACME, fldPath.Child("acme"))...)
	}
	if crt.KeySize < 0 {
		el = append(el, field.Invalid(fldPath.Child("keySize"), crt.KeySize, "cannot be less than zero"))
	}
	switch crt.KeyAlgorithm {
	case v1alpha1.KeyAlgorithm(""):
	case v1alpha1.RSAKeyAlgorithm:
		if crt.KeySize > 0 && (crt.KeySize < 2048 || crt.KeySize > 8192) {
			el = append(el, field.Invalid(fldPath.Child("keySize"), crt.KeySize, "must be between 2048 & 8192 for rsa keyAlgorithm"))
		}
	case v1alpha1.ECDSAKeyAlgorithm:
		if crt.KeySize > 0 && crt.KeySize != 256 && crt.KeySize != 384 && crt.KeySize != 521 {
			el = append(el, field.NotSupported(fldPath.Child("keySize"), crt.KeySize, []string{"256", "384", "521"}))
		}
	default:
		el = append(el, field.Invalid(fldPath.Child("keyAlgorithm"), crt.KeyAlgorithm, "must be either empty or one of rsa or ecdsa"))
	}

	return el
}

// validateACMEConfigForAllDNSNames will ensure that if the provided Certificate
// specifies any ACME configuration, all domains listed on the Certificate have
// a configuration entry.
func validateACMEConfigForAllDNSNames(a *v1alpha1.CertificateSpec, fldPath *field.Path) field.ErrorList {
	if a.ACME == nil {
		return nil
	}
	el := field.ErrorList{}
	acmeFldPath := fldPath.Child("acme")
	errFn := func(s string) string {
		return fmt.Sprintf("no ACME solver configuration specified for domain %q", s)
	}
	if a.CommonName != "" {
		cfg := v1alpha1.ConfigForDomain(a.ACME.Config, a.CommonName)
		if cfg == nil || len(cfg.Domains) == 0 {
			el = append(el, field.Required(acmeFldPath.Child("config"), errFn(a.CommonName)))
		}
	}
	for _, d := range a.DNSNames {
		cfg := v1alpha1.ConfigForDomain(a.ACME.Config, d)
		if cfg == nil || len(cfg.Domains) == 0 {
			el = append(el, field.Required(acmeFldPath.Child("config"), errFn(d)))
		}
	}
	return el
}

func ValidateACMECertificateConfig(a *v1alpha1.ACMECertificateConfig, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	for i, cfg := range a.Config {
		el = append(el, ValidateDomainSolverConfig(&cfg, fldPath.Child("config").Index(i))...)
	}
	return el
}

func ValidateDomainSolverConfig(a *v1alpha1.DomainSolverConfig, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if len(a.Domains) == 0 {
		el = append(el, field.Required(fldPath.Child("domains"), "at least one domain must be specified"))
	}
	numTypes := 0
	if a.DNS01 != nil {
		numTypes++
		el = append(el, ValidateDNS01SolverConfig(a.DNS01, fldPath.Child("dns01"))...)
	}
	if a.HTTP01 != nil {
		if numTypes > 0 {
			el = append(el, field.Forbidden(fldPath.Child("http01"), "may not specify more than one solver type"))
		} else {
			numTypes++
			el = append(el, ValidateHTTP01SolverConfig(a.HTTP01, fldPath.Child("http01"))...)
		}
	}
	if numTypes == 0 {
		el = append(el, field.Required(fldPath, "at least one solver must be configured"))
	}
	return el
}

func ValidateDNS01SolverConfig(a *v1alpha1.DNS01SolverConfig, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if a.Provider == "" {
		el = append(el, field.Required(fldPath.Child("provider"), "provider name must be set"))
	}
	return el
}

func ValidateHTTP01SolverConfig(a *v1alpha1.HTTP01SolverConfig, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if a.Ingress != "" && a.IngressClass != nil {
		el = append(el, field.Forbidden(fldPath, "only one of 'ingress' and 'ingressClass' should be specified"))
	}
	// TODO: ensure 'ingress' is a valid resource name (i.e. DNS name)
	return el
}
