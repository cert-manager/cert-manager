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
	"fmt"
	"net"
	"net/mail"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	internalcmapi "github.com/cert-manager/cert-manager/pkg/internal/apis/certmanager"
	cmmeta "github.com/cert-manager/cert-manager/pkg/internal/apis/meta"
)

// Validation functions for cert-manager Certificate types

func ValidateCertificateSpec(crt *internalcmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if crt.SecretName == "" {
		el = append(el, field.Required(fldPath.Child("secretName"), "must be specified"))
	}

	el = append(el, validateIssuerRef(crt.IssuerRef, fldPath)...)

	if len(crt.CommonName) == 0 && len(crt.DNSNames) == 0 && len(crt.URISANs) == 0 && len(crt.EmailSANs) == 0 && len(crt.IPAddresses) == 0 {
		el = append(el, field.Invalid(fldPath, "", "at least one of commonName, dnsNames, uris ipAddresses, or emailAddresses must be set"))
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

	if crt.PrivateKey != nil {
		switch crt.PrivateKey.Algorithm {
		case "", internalcmapi.RSAKeyAlgorithm:
			if crt.PrivateKey.Size > 0 && (crt.PrivateKey.Size < 2048 || crt.PrivateKey.Size > 8192) {
				el = append(el, field.Invalid(fldPath.Child("privateKey", "size"), crt.PrivateKey.Size, "must be between 2048 & 8192 for rsa keyAlgorithm"))
			}
		case internalcmapi.ECDSAKeyAlgorithm:
			if crt.PrivateKey.Size > 0 && crt.PrivateKey.Size != 256 && crt.PrivateKey.Size != 384 && crt.PrivateKey.Size != 521 {
				el = append(el, field.NotSupported(fldPath.Child("privateKey", "size"), crt.PrivateKey.Size, []string{"256", "384", "521"}))
			}
		default:
			el = append(el, field.Invalid(fldPath.Child("privateKey", "algorithm"), crt.PrivateKey.Algorithm, "must be either empty or one of rsa or ecdsa"))
		}
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
	crt := obj.(*internalcmapi.Certificate)
	allErrs := ValidateCertificateSpec(&crt.Spec, field.NewPath("spec"))
	return allErrs
}

func ValidateUpdateCertificate(oldObj, obj runtime.Object) field.ErrorList {
	crt := obj.(*internalcmapi.Certificate)
	allErrs := ValidateCertificateSpec(&crt.Spec, field.NewPath("spec"))
	return allErrs
}

func validateIssuerRef(issuerRef cmmeta.ObjectReference, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	issuerRefPath := fldPath.Child("issuerRef")
	if issuerRef.Name == "" {
		el = append(el, field.Required(issuerRefPath.Child("name"), "must be specified"))
	}
	if issuerRef.Group == "" || issuerRef.Group == internalcmapi.SchemeGroupVersion.Group {
		switch issuerRef.Kind {
		case "":
		case "Issuer", "ClusterIssuer":
		default:
			el = append(el, field.Invalid(issuerRefPath.Child("kind"), issuerRef.Kind, "must be one of Issuer or ClusterIssuer"))
		}
	}
	return el
}

func validateIPAddresses(a *internalcmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
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

func validateEmailAddresses(a *internalcmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	if len(a.EmailSANs) <= 0 {
		return nil
	}
	el := field.ErrorList{}
	for i, d := range a.EmailSANs {
		e, err := mail.ParseAddress(d)
		if err != nil {
			el = append(el, field.Invalid(fldPath.Child("emailAddresses").Index(i), d, fmt.Sprintf("invalid email address: %s", err)))
		} else if e.Address != d {
			// Go accepts email names as per RFC 5322 (name <email>)
			// This checks if the supplied value only contains the email address and nothing else
			el = append(el, field.Invalid(fldPath.Child("emailAddresses").Index(i), d, "invalid email address: make sure the supplied value only contains the email address itself"))
		}
	}
	return el
}

func validateUsages(a *internalcmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	for i, u := range a.Usages {
		_, kok := util.KeyUsageType(cmapi.KeyUsage(u))
		_, ekok := util.ExtKeyUsageType(cmapi.KeyUsage(u))
		if !kok && !ekok {
			el = append(el, field.Invalid(fldPath.Child("usages").Index(i), u, "unknown keyusage"))
		}
	}
	return el
}

func ValidateDuration(crt *internalcmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	duration := util.DefaultCertDuration(crt.Duration)
	renewBefore := cmapi.DefaultRenewBefore
	if crt.RenewBefore != nil {
		renewBefore = crt.RenewBefore.Duration
	}
	if duration < cmapi.MinimumCertificateDuration {
		el = append(el, field.Invalid(fldPath.Child("duration"), duration, fmt.Sprintf("certificate duration must be greater than %s", cmapi.MinimumCertificateDuration)))
	}
	if renewBefore < cmapi.MinimumRenewBefore {
		el = append(el, field.Invalid(fldPath.Child("renewBefore"), renewBefore, fmt.Sprintf("certificate renewBefore must be greater than %s", cmapi.MinimumRenewBefore)))
	}
	if duration <= renewBefore {
		el = append(el, field.Invalid(fldPath.Child("renewBefore"), renewBefore, fmt.Sprintf("certificate duration %s must be greater than renewBefore %s", duration, renewBefore)))
	}
	return el
}
