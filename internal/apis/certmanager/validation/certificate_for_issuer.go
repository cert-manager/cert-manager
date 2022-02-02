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

	"k8s.io/apimachinery/pkg/util/validation/field"

	cmapi "github.com/cert-manager/cert-manager/internal/apis/certmanager"
)

func ValidateCertificateForIssuer(crt *cmapi.Certificate, issuerObj cmapi.GenericIssuer) field.ErrorList {
	el := field.ErrorList{}

	path := field.NewPath("spec")

	switch {
	case issuerObj.GetSpec().ACME != nil:
		el = append(el, ValidateCertificateForACMEIssuer(&crt.Spec, issuerObj.GetSpec(), path)...)
	case issuerObj.GetSpec().CA != nil:
	case issuerObj.GetSpec().Vault != nil:
		el = append(el, ValidateCertificateForVaultIssuer(&crt.Spec, issuerObj.GetSpec(), path)...)
	case issuerObj.GetSpec().SelfSigned != nil:
	case issuerObj.GetSpec().Venafi != nil:
	default:
		el = append(el, field.Invalid(path, "", fmt.Sprintf("no issuer specified for Issuer '%s/%s'", issuerObj.GetObjectMeta().Namespace, issuerObj.GetObjectMeta().Name)))
	}

	return el
}

func ValidateCertificateForACMEIssuer(crt *cmapi.CertificateSpec, issuer *cmapi.IssuerSpec, specPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	if crt.IsCA {
		el = append(el, field.Invalid(specPath.Child("isCA"), crt.IsCA, "ACME does not support CA certificates"))
	}

	if crt.Subject != nil && len(crt.Subject.Organizations) != 0 {
		el = append(el, field.Invalid(specPath.Child("subject", "organizations"), crt.Subject.Organizations, "ACME does not support setting the organization name"))
	}

	if crt.Duration != nil {
		el = append(el, field.Invalid(specPath.Child("duration"), crt.Duration, "ACME does not support certificate durations"))
	}

	if len(crt.IPAddresses) != 0 {
		el = append(el, field.Invalid(specPath.Child("ipAddresses"), crt.IPAddresses, "ACME does not support certificate ip addresses"))
	}

	return el
}

func ValidateCertificateForVaultIssuer(crt *cmapi.CertificateSpec, issuer *cmapi.IssuerSpec, specPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	if crt.IsCA {
		el = append(el, field.Invalid(specPath.Child("isCA"), crt.IsCA, "Vault issuer does not currently support CA certificates"))
	}

	if crt.Subject != nil && len(crt.Subject.Organizations) != 0 {
		el = append(el, field.Invalid(specPath.Child("subject", "organizations"), crt.Subject.Organizations, "Vault issuer does not currently support setting the organization name"))
	}

	return el
}
