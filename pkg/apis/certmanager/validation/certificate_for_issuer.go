package validation

import (
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
)

func ValidateCertificateForIssuer(crt *v1alpha1.Certificate, issuerObj v1alpha1.GenericIssuer) field.ErrorList {
	el := field.ErrorList{}

	path := field.NewPath("spec")

	issuerType, err := controller.NameForIssuer(issuerObj)
	if err != nil {
		el = append(el, field.Invalid(path, err.Error(), err.Error()))
		return el
	}

	switch issuerType {
	case controller.IssuerACME:
		el = append(el, ValidateCertificateForACMEIssuer(&crt.Spec, issuerObj.GetSpec(), path)...)
	case controller.IssuerCA:
		el = append(el, ValidateCertificateForCAIssuer(&crt.Spec, issuerObj.GetSpec(), path)...)
	case controller.IssuerVault:
		el = append(el, ValidateCertificateForVaultIssuer(&crt.Spec, issuerObj.GetSpec(), path)...)
	case controller.IssuerSelfSigned:
		el = append(el, ValidateCertificateForSelfSignedIssuer(&crt.Spec, issuerObj.GetSpec(), path)...)
	}

	return el
}

func ValidateCertificateForACMEIssuer(crt *v1alpha1.CertificateSpec, issuer *v1alpha1.IssuerSpec, specPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	if crt.KeyAlgorithm != v1alpha1.KeyAlgorithm("") && crt.KeyAlgorithm != v1alpha1.RSAKeyAlgorithm {
		el = append(el, field.Invalid(specPath.Child("keyAlgorithm"), crt.KeyAlgorithm, "ACME key algorithm must be RSA"))
	}

	return el
}

func ValidateCertificateForCAIssuer(crt *v1alpha1.CertificateSpec, issuer *v1alpha1.IssuerSpec, specPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	return el
}

func ValidateCertificateForVaultIssuer(crt *v1alpha1.CertificateSpec, issuer *v1alpha1.IssuerSpec, specPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	return el
}

func ValidateCertificateForSelfSignedIssuer(crt *v1alpha1.CertificateSpec, issuer *v1alpha1.IssuerSpec, specPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	return el
}
