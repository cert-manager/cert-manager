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

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

// Validation functions for cert-manager v1alpha2 Certificate types

func ValidateCertificateSpec(crt *v1alpha2.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if crt.SecretName == "" {
		el = append(el, field.Required(fldPath.Child("secretName"), "must be specified"))
	}

	el = append(el, validateIssuerRef(crt.IssuerRef, fldPath)...)

	if len(crt.CommonName) == 0 && len(crt.DNSNames) == 0 && len(crt.URISANs) == 0 {
		el = append(el, field.Required(fldPath.Child("commonName", "dnsNames", "uriSANs"),
			"at least one of commonName, dnsNames, or uriSANs must be set"))
	}

	// if a common name has been specified, ensure it is no longer than 64 chars
	if len(crt.CommonName) > 64 {
		el = append(el, field.TooLong(fldPath.Child("commonName"), crt.CommonName, 64))
	}

	if len(crt.IPAddresses) > 0 {
		el = append(el, validateIPAddresses(crt, fldPath)...)
	}
	if crt.KeySize < 0 {
		el = append(el, field.Invalid(fldPath.Child("keySize"), crt.KeySize, "cannot be less than zero"))
	}
	switch crt.KeyAlgorithm {
	case v1alpha2.KeyAlgorithm(""):
	case v1alpha2.RSAKeyAlgorithm:
		if crt.KeySize > 0 && (crt.KeySize < 2048 || crt.KeySize > 8192) {
			el = append(el, field.Invalid(fldPath.Child("keySize"), crt.KeySize, "must be between 2048 & 8192 for rsa keyAlgorithm"))
		}
	case v1alpha2.ECDSAKeyAlgorithm:
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
	switch crt.KeyEncoding {
	case v1alpha2.KeyEncoding(""), v1alpha2.PKCS1, v1alpha2.PKCS8:
	default:
		el = append(el, field.Invalid(fldPath.Child("keyEncoding"), crt.KeyEncoding, "must be either empty or one of pkcs1 or pkcs8"))
	}
	return el
}

func ValidateCertificate(obj runtime.Object) field.ErrorList {
	crt := obj.(*v1alpha2.Certificate)
	allErrs := ValidateCertificateSpec(&crt.Spec, field.NewPath("spec"))
	return allErrs
}

func validateIssuerRef(issuerRef cmmeta.ObjectReference, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	issuerRefPath := fldPath.Child("issuerRef")
	if issuerRef.Name == "" {
		el = append(el, field.Required(issuerRefPath.Child("name"), "must be specified"))
	}
	if issuerRef.Group == "" || issuerRef.Group == v1alpha2.SchemeGroupVersion.Group {
		switch issuerRef.Kind {
		case "":
		case "Issuer", "ClusterIssuer":
		default:
			el = append(el, field.Invalid(issuerRefPath.Child("kind"), issuerRef.Kind, "must be one of Issuer or ClusterIssuer"))
		}
	}
	return el
}

func validateIPAddresses(a *v1alpha2.CertificateSpec, fldPath *field.Path) field.ErrorList {
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

func validateUsages(a *v1alpha2.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	for i, u := range a.Usages {
		_, kok := util.KeyUsageType(u)
		_, ekok := util.ExtKeyUsageType(u)
		if !kok && !ekok {
			el = append(el, field.Invalid(fldPath.Child("usages").Index(i), u, "unknown keyusage"))
		}
	}
	return el
}

func ValidateDuration(crt *v1alpha2.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	duration := util.DefaultCertDuration(crt.Duration)
	renewBefore := v1alpha2.DefaultRenewBefore
	if crt.RenewBefore != nil {
		renewBefore = crt.RenewBefore.Duration
	}
	if duration < v1alpha2.MinimumCertificateDuration {
		el = append(el, field.Invalid(fldPath.Child("duration"), duration, fmt.Sprintf("certificate duration must be greater than %s", v1alpha2.MinimumCertificateDuration)))
	}
	if renewBefore < v1alpha2.MinimumRenewBefore {
		el = append(el, field.Invalid(fldPath.Child("renewBefore"), renewBefore, fmt.Sprintf("certificate renewBefore must be greater than %s", v1alpha2.MinimumRenewBefore)))
	}
	if duration <= renewBefore {
		el = append(el, field.Invalid(fldPath.Child("renewBefore"), renewBefore, fmt.Sprintf("certificate duration %s must be greater than renewBefore %s", duration, renewBefore)))
	}
	return el
}
