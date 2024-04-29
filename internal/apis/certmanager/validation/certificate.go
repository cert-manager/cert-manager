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
	"strings"
	"unicode/utf8"

	admissionv1 "k8s.io/api/admission/v1"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	metavalidation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"

	internalcmapi "github.com/cert-manager/cert-manager/internal/apis/certmanager"
	cmmeta "github.com/cert-manager/cert-manager/internal/apis/meta"
	"github.com/cert-manager/cert-manager/internal/webhook/feature"
	"github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// Validation functions for cert-manager Certificate types

func ValidateCertificateSpec(crt *internalcmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if crt.SecretName == "" {
		el = append(el, field.Required(fldPath.Child("secretName"), "must be specified"))
	} else {
		for _, msg := range apivalidation.NameIsDNSSubdomain(crt.SecretName, false) {
			el = append(el, field.Invalid(fldPath.Child("secretName"), crt.SecretName, msg))
		}
	}

	el = append(el, validateIssuerRef(crt.IssuerRef, fldPath)...)

	var commonName = crt.CommonName
	if crt.LiteralSubject != "" {
		if !utilfeature.DefaultFeatureGate.Enabled(feature.LiteralCertificateSubject) {
			el = append(el, field.Forbidden(fldPath.Child("literalSubject"), "Feature gate LiteralCertificateSubject must be enabled on both webhook and controller to use the alpha `literalSubject` field"))
		}

		if len(commonName) != 0 {
			el = append(el, field.Invalid(fldPath.Child("commonName"), commonName, "When providing a `LiteralSubject` no `commonName` may be provided."))
		}

		if crt.Subject != nil && (len(crt.Subject.Organizations) > 0 ||
			len(crt.Subject.Countries) > 0 ||
			len(crt.Subject.OrganizationalUnits) > 0 ||
			len(crt.Subject.Localities) > 0 ||
			len(crt.Subject.Provinces) > 0 ||
			len(crt.Subject.StreetAddresses) > 0 ||
			len(crt.Subject.PostalCodes) > 0 ||
			len(crt.Subject.SerialNumber) > 0) {
			el = append(el, field.Invalid(fldPath.Child("subject"), crt.Subject, "When providing a `LiteralSubject` no `Subject` properties may be provided."))
		}

		sequence, err := pki.UnmarshalSubjectStringToRDNSequence(crt.LiteralSubject)
		if err != nil {
			el = append(el, field.Invalid(fldPath.Child("literalSubject"), crt.LiteralSubject, err.Error()))
		}

		// Must contain a CN
		for _, rdns := range sequence {
			for _, atv := range rdns {
				if atv.Type.Equal(pki.OIDConstants.CommonName) {
					if str, ok := atv.Value.(string); ok {
						commonName = str
					} else {
						el = append(el, field.Invalid(fldPath.Child("literalSubject"), atv.Value, "Field with type CN should be a string"))
					}
				}
			}
		}

		// Should not contain unrecognized OIDs
		for _, rdns := range sequence {
			for _, atv := range rdns {
				if atv.Type.Equal(nil) {
					el = append(el, field.Invalid(fldPath.Child("literalSubject"), crt.LiteralSubject, fmt.Sprintf("Literal subject contains unrecognized key with value [%s]", atv.Value)))
				}
			}
		}
	}

	if len(commonName) == 0 &&
		len(crt.DNSNames) == 0 &&
		len(crt.URIs) == 0 &&
		len(crt.EmailAddresses) == 0 &&
		len(crt.IPAddresses) == 0 &&
		len(crt.OtherNames) == 0 {
		el = append(el, field.Invalid(fldPath, "", "at least one of commonName (from the commonName field or from a literalSubject), dnsNames, uriSANs, ipAddresses, emailSANs or otherNames must be set"))
	}

	// if a common name has been specified, ensure it is no longer than 64 chars
	if len(commonName) > 64 {
		el = append(el, field.TooLong(fldPath.Child("commonName"), commonName, 64))
	}

	if len(crt.IPAddresses) > 0 {
		el = append(el, validateIPAddresses(crt, fldPath)...)
	}

	if len(crt.EmailAddresses) > 0 {
		el = append(el, validateEmailAddresses(crt, fldPath)...)
	}

	if len(crt.OtherNames) > 0 {
		if !utilfeature.DefaultFeatureGate.Enabled(feature.OtherNames) {
			el = append(el, field.Forbidden(fldPath.Child("OtherNames"), "Feature gate OtherNames must be enabled on both webhook and controller to use the alpha `otherNames` field"))
		} else {
			for i, otherName := range crt.OtherNames {
				if otherName.OID == "" {
					el = append(el, field.Required(fldPath.Child("otherNames").Index(i).Child("oid"), "must be specified"))
				}

				if _, err := pki.ParseObjectIdentifier(otherName.OID); err != nil {
					el = append(el, field.Invalid(fldPath.Child("otherNames").Index(i).Child("oid"), otherName.OID, "oid syntax invalid"))
				}

				if otherName.UTF8Value == "" || !utf8.ValidString(otherName.UTF8Value) {
					el = append(el, field.Required(fldPath.Child("otherNames").Index(i).Child("utf8Value"), "must be set to a valid non-empty UTF8 string"))
				}
			}
		}
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
		case internalcmapi.Ed25519KeyAlgorithm:
			break
		default:
			el = append(el, field.Invalid(fldPath.Child("privateKey", "algorithm"), crt.PrivateKey.Algorithm, "must be either empty or one of rsa, ecdsa or ed25519"))
		}
	}

	if crt.Duration != nil || crt.RenewBefore != nil {
		el = append(el, ValidateDuration(crt, fldPath)...)
	}
	if len(crt.Usages) > 0 {
		el = append(el, validateUsages(crt, fldPath)...)
	}
	if crt.RevisionHistoryLimit != nil && *crt.RevisionHistoryLimit < 1 {
		el = append(el, field.Invalid(fldPath.Child("revisionHistoryLimit"), *crt.RevisionHistoryLimit, "must not be less than 1"))
	}

	if crt.SecretTemplate != nil {
		if len(crt.SecretTemplate.Labels) > 0 {
			el = append(el, validateSecretTemplateLabels(crt, fldPath)...)
		}
		if len(crt.SecretTemplate.Annotations) > 0 {
			el = append(el, validateSecretTemplateAnnotations(crt, fldPath)...)
		}
	}

	if crt.NameConstraints != nil {
		if !utilfeature.DefaultFeatureGate.Enabled(feature.NameConstraints) {
			el = append(el, field.Forbidden(fldPath.Child("nameConstraints"), "feature gate NameConstraints must be enabled"))
		} else {
			if !crt.IsCA {
				el = append(el, field.Invalid(fldPath.Child("nameConstraints"), crt.NameConstraints, "isCa should be true when nameConstraints is set"))
			}

			if crt.NameConstraints.Permitted == nil && crt.NameConstraints.Excluded == nil {
				el = append(el, field.Invalid(fldPath.Child("nameConstraints"), crt.NameConstraints, "either permitted or excluded must be set"))
			}
		}
	}

	el = append(el, validateAdditionalOutputFormats(crt, fldPath)...)

	return el
}

func ValidateCertificate(a *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, []string) {
	crt := obj.(*internalcmapi.Certificate)
	allErrs := ValidateCertificateSpec(&crt.Spec, field.NewPath("spec"))
	return allErrs, nil
}

func ValidateUpdateCertificate(a *admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (field.ErrorList, []string) {
	crt := obj.(*internalcmapi.Certificate)
	allErrs := ValidateCertificateSpec(&crt.Spec, field.NewPath("spec"))
	return allErrs, nil
}

func validateIssuerRef(issuerRef cmmeta.ObjectReference, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	issuerRefPath := fldPath.Child("issuerRef")
	if issuerRef.Name == "" {
		// all issuerRefs must specify a name
		el = append(el, field.Required(issuerRefPath.Child("name"), "must be specified"))
	}

	if issuerRef.Group == "" || issuerRef.Group == internalcmapi.SchemeGroupVersion.Group {
		// if the user leaves the group blank, it's effectively defaulted to the built-in issuers (i.e. cert-manager.io)
		// if the cert-manager.io group is used, we can do extra validation on the Kind
		// if an external group is used, we don't have a mechanism currently to determine which Kinds are valid for those groups
		// so we don't check
		switch issuerRef.Kind {
		case "":
			// do nothing

		case "Issuer", "ClusterIssuer":
			// do nothing

		default:
			kindPath := issuerRefPath.Child("kind")
			errMsg := "must be one of Issuer or ClusterIssuer"

			if issuerRef.Group == "" {
				// Sometimes the user sets a kind for an external issuer (e.g. "AWSPCAClusterIssuer" or "VenafiIssuer") but forgets
				// to set the group (an easy mistake to make - see https://github.com/cert-manager/csi-driver/issues/197).
				// If the users forgets the group but otherwise has a correct Kind set for an external issuer, we can give a hint
				// as to what they need to do to fix.

				// If the user explicitly set the group to the cert-manager group though, we don't give the hint
				errMsg += fmt.Sprintf(" (did you forget to set %s?)", kindPath.Child("group").String())
			}

			el = append(el, field.Invalid(kindPath, issuerRef.Kind, errMsg))
		}
	}

	return el
}

func validateIPAddresses(a *internalcmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	if len(a.IPAddresses) == 0 {
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
	if len(a.EmailAddresses) == 0 {
		return nil
	}
	el := field.ErrorList{}
	for i, d := range a.EmailAddresses {
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

func validateSecretTemplateLabels(crt *internalcmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	return metavalidation.ValidateLabels(crt.SecretTemplate.Labels, fldPath.Child("secretTemplate", "labels"))
}

func validateSecretTemplateAnnotations(crt *internalcmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	secretTemplateAnnotationsPath := fldPath.Child("secretTemplate", "annotations")
	for a := range crt.SecretTemplate.Annotations {
		if strings.HasPrefix(a, "cert-manager.io/") && a != "cert-manager.io/allow-direct-injection" {
			el = append(el, field.Invalid(secretTemplateAnnotationsPath, a, "cert-manager.io/* annotations are not allowed"))
		}
	}

	el = append(el, apivalidation.ValidateAnnotations(crt.SecretTemplate.Annotations, secretTemplateAnnotationsPath)...)
	return el
}

func ValidateDuration(crt *internalcmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	duration := util.DefaultCertDuration(crt.Duration)
	if duration < cmapi.MinimumCertificateDuration {
		el = append(el, field.Invalid(fldPath.Child("duration"), duration, fmt.Sprintf("certificate duration must be greater than %s", cmapi.MinimumCertificateDuration)))
	}
	// If spec.renewBefore is set, check that it is not less than the minimum.
	if crt.RenewBefore != nil && crt.RenewBefore.Duration < cmapi.MinimumRenewBefore {
		el = append(el, field.Invalid(fldPath.Child("renewBefore"), crt.RenewBefore.Duration, fmt.Sprintf("certificate renewBefore must be greater than %s", cmapi.MinimumRenewBefore)))
	}
	// If spec.renewBefore is set, it must be less than the duration.
	if crt.RenewBefore != nil && crt.RenewBefore.Duration >= duration {
		el = append(el, field.Invalid(fldPath.Child("renewBefore"), crt.RenewBefore.Duration, fmt.Sprintf("certificate duration %s must be greater than renewBefore %s", duration, crt.RenewBefore.Duration)))
	}
	return el
}

func validateAdditionalOutputFormats(crt *internalcmapi.CertificateSpec, fldPath *field.Path) field.ErrorList {
	var el field.ErrorList

	if !utilfeature.DefaultFeatureGate.Enabled(feature.AdditionalCertificateOutputFormats) {
		if len(crt.AdditionalOutputFormats) > 0 {
			el = append(el, field.Forbidden(fldPath.Child("additionalOutputFormats"), "feature gate AdditionalCertificateOutputFormats must be enabled"))
		}
		return el
	}

	// Ensure the set of output formats is unique, keyed on "Type".
	aofSet := sets.NewString()
	for _, val := range crt.AdditionalOutputFormats {
		if aofSet.Has(string(val.Type)) {
			el = append(el, field.Duplicate(fldPath.Child("additionalOutputFormats").Key("type"), string(val.Type)))
			continue
		}
		aofSet.Insert(string(val.Type))
	}

	return el
}
