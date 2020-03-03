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
	"fmt"
	"net"
	"net/mail"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/jetstack/cert-manager/pkg/api/util"
	cmapiv1alpha2 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmapi "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
	cmmeta "github.com/jetstack/cert-manager/pkg/internal/apis/meta"
)

// Validation functions for cert-manager Certificate types

func ValidateCertificateSpec(crt *cmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if crt.SecretName == "" {
		el = append(el, field.Required(fldPath.Child("secretName"), "must be specified"))
	}

	el = append(el, validateIssuerRef(crt.IssuerRef, fldPath)...)

	if len(crt.CommonName) == 0 && len(crt.DNSNames) == 0 && len(crt.URISANs) == 0 && len(crt.EmailSANs) == 0 {
		el = append(el, field.Invalid(fldPath, "", "at least one of commonName, dnsNames, uriSANs or emailSANs must be set"))
	}

	// if a common name has been specified, ensure it is no longer than 64 chars
	if len(crt.CommonName) > 64 {
		el = append(el, field.TooLong(fldPath.Child("commonName"), crt.CommonName, 64))
	}

	if len(crt.IPAddresses) > 0 {
		el = append(el, validateIPAddresses(crt, fldPath)...)
	}

	if len(crt.EmailSANs) > 0 {
		el = append(el, validateEmailAddresses(crt, fldPath)...)
	}

	switch crt.KeyAlgorithm {
	case cmapi.KeyAlgorithm(""):
	case cmapi.RSAKeyAlgorithm:
		if crt.KeySize > 0 && (crt.KeySize < 2048 || crt.KeySize > 8192) {
			el = append(el, field.Invalid(fldPath.Child("keySize"), crt.KeySize, "must be between 2048 & 8192 for rsa keyAlgorithm"))
		}
	case cmapi.ECDSAKeyAlgorithm:
		if crt.KeySize > 0 && crt.KeySize != 256 && crt.KeySize != 384 && crt.KeySize != 521 {
			el = append(el, field.NotSupported(fldPath.Child("keySize"), crt.KeySize, []string{"256", "384", "521"}))
		}
	default:
		el = append(el, field.Invalid(fldPath.Child("keyAlgorithm"), crt.KeyAlgorithm, "must be either empty or one of rsa or ecdsa"))
	}

	if crt.Duration != nil || crt.RenewBefore != nil {
		el = append(el, ValidateDuration(crt, fldPath)...)
	}
	if len(crt.Usages) > 0 {
		el = append(el, validateUsages(crt, fldPath)...)
	}
	return el
}

func ValidateCertificate(obj runtime.Object) field.ErrorList {
	crt := obj.(*cmapi.Certificate)
	allErrs := ValidateCertificateSpec(&crt.Spec, field.NewPath("spec"))
	return allErrs
}

func validateIssuerRef(issuerRef cmmeta.ObjectReference, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	issuerRefPath := fldPath.Child("issuerRef")
	if issuerRef.Name == "" {
		el = append(el, field.Required(issuerRefPath.Child("name"), "must be specified"))
	}
	if issuerRef.Group == "" || issuerRef.Group == cmapi.SchemeGroupVersion.Group {
		switch issuerRef.Kind {
		case "":
		case "Issuer", "ClusterIssuer":
		default:
			el = append(el, field.Invalid(issuerRefPath.Child("kind"), issuerRef.Kind, "must be one of Issuer or ClusterIssuer"))
		}
	}
	return el
}

func validateIPAddresses(a *cmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	if len(a.IPAddresses) <= 0 {
		return nil
	}
	el := field.ErrorList{}
	for i, d := range a.IPAddresses {
		ip := net.ParseIP(d)
		if ip == nil {
			el = append(el, field.Invalid(fldPath.Child("ipAddresses").Index(i), d, "invalid IP address"))
		}
	}
	return el
}

func validateEmailAddresses(a *cmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	if len(a.EmailSANs) <= 0 {
		return nil
	}
	el := field.ErrorList{}
	for i, d := range a.EmailSANs {
		e, err := mail.ParseAddress(d)
		if err != nil {
			el = append(el, field.Invalid(fldPath.Child("emailSANs").Index(i), d, fmt.Sprintf("invalid email address: %s", err)))
		} else if e.Address != d {
			// Go accepts email names as per RFC 5322 (name <email>)
			// This checks if the supplied value only contains the email address and nothing else
			el = append(el, field.Invalid(fldPath.Child("emailSANs").Index(i), d, "invalid email address: make sure the supplied value only contains the email address itself"))
		}
	}
	return el
}

func validateUsages(a *cmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	for i, u := range a.Usages {
		_, kok := util.KeyUsageType(cmapiv1alpha2.KeyUsage(u))
		_, ekok := util.ExtKeyUsageType(cmapiv1alpha2.KeyUsage(u))
		if !kok && !ekok {
			el = append(el, field.Invalid(fldPath.Child("usages").Index(i), u, "unknown keyusage"))
		}
	}
	return el
}

func ValidateDuration(crt *cmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	duration := util.DefaultCertDuration(crt.Duration)
	renewBefore := cmapiv1alpha2.DefaultRenewBefore
	if crt.RenewBefore != nil {
		renewBefore = crt.RenewBefore.Duration
	}
	if duration < cmapiv1alpha2.MinimumCertificateDuration {
		el = append(el, field.Invalid(fldPath.Child("duration"), duration, fmt.Sprintf("certificate duration must be greater than %s", cmapiv1alpha2.MinimumCertificateDuration)))
	}
	if renewBefore < cmapiv1alpha2.MinimumRenewBefore {
		el = append(el, field.Invalid(fldPath.Child("renewBefore"), renewBefore, fmt.Sprintf("certificate renewBefore must be greater than %s", cmapiv1alpha2.MinimumRenewBefore)))
	}
	if duration <= renewBefore {
		el = append(el, field.Invalid(fldPath.Child("renewBefore"), renewBefore, fmt.Sprintf("certificate duration %s must be greater than renewBefore %s", duration, renewBefore)))
	}
	return el
}
