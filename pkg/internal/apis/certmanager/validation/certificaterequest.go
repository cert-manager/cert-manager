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
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"reflect"

	"github.com/kr/pretty"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	v1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmapi "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

func ValidateCertificateRequest(obj runtime.Object) field.ErrorList {
	cr := obj.(*cmapi.CertificateRequest)
	allErrs := ValidateCertificateRequestSpec(&cr.Spec, field.NewPath("spec"))
	return allErrs
}

func ValidateCertificateRequestSpec(crSpec *cmapi.CertificateRequestSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	el = append(el, validateIssuerRef(crSpec.IssuerRef, fldPath)...)

	if len(crSpec.Request) == 0 {
		el = append(el, field.Required(fldPath.Child("request"), "must be specified"))
	} else {
		csr, err := pki.DecodeX509CertificateRequestBytes(crSpec.Request)
		if err != nil {
			el = append(el, field.Invalid(fldPath.Child("request"), crSpec.Request, fmt.Sprintf("failed to decode csr: %s", err)))
		} else {
			// only compare usages if set on CR and in the CSR
			if len(crSpec.Usages) > 0 && len(csr.ExtraExtensions) > 0 {
				csrUsages, err := getCSRKeyUsage(crSpec, fldPath, csr, err, el)
				if len(err) > 0 {
					el = append(el, err...)
				} else if !reflect.DeepEqual(csrUsages, crSpec.Usages) {
					el = append(el, field.Invalid(fldPath.Child("request"), crSpec.Request, fmt.Sprintf("csr key usages do not match specified usages: %s", pretty.Diff(csrUsages, crSpec.Usages))))
				}
			}
		}
	}

	return el
}

func getCSRKeyUsage(crSpec *cmapi.CertificateRequestSpec, fldPath *field.Path, csr *x509.CertificateRequest, err error, el field.ErrorList) ([]v1.KeyUsage, field.ErrorList) {
	var ekus []x509.ExtKeyUsage
	var ku x509.KeyUsage

	for _, extention := range csr.ExtraExtensions {
		if reflect.DeepEqual(extention.Id, pki.OIDExtensionExtendedKeyUsage) {
			var asn1ExtendedUsages []asn1.ObjectIdentifier
			_, err = asn1.Unmarshal(extention.Value, &asn1ExtendedUsages)
			if err != nil {
				el = append(el, field.Invalid(fldPath.Child("request"), crSpec.Request, fmt.Sprintf("failed to decode csr extended usages: %s", err)))
			} else {
				for _, asnExtUsage := range asn1ExtendedUsages {
					eku, ok := pki.ExtKeyUsageFromOID(asnExtUsage)
					if ok {
						ekus = append(ekus, eku)
					}
				}
			}
		}
		if reflect.DeepEqual(extention.Id, pki.OIDExtensionKeyUsage) {
			// RFC 5280, 4.2.1.3
			var asn1bits asn1.BitString
			_, err := asn1.Unmarshal(extention.Value, &asn1bits)
			if err != nil {
				el = append(el, field.Invalid(fldPath.Child("request"), crSpec.Request, fmt.Sprintf("failed to decode csr usages: %s", err)))
			} else {
				var usage int
				for i := 0; i < 9; i++ {
					if asn1bits.At(i) != 0 {
						usage |= 1 << uint(i)
					}
				}
				ku = x509.KeyUsage(usage)
			}
		}
	}

	return pki.BuildCertManagerKeyUsages(ku, ekus), el
}
