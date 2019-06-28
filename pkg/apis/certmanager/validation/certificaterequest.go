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
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func ValidateCertificateRequest(cr *v1alpha1.CertificateRequest) field.ErrorList {
	allErrs := ValidateCertificateRequestSpec(&cr.Spec, field.NewPath("spec"))
	return allErrs
}

func ValidateCertificateRequestSpec(crSpec *v1alpha1.CertificateRequestSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	if len(crSpec.CSRPEM) == 0 {
		el = append(el, field.Required(fldPath.Child("csr"), "must be specified"))
	}

	if len(crSpec.IssuerRef.Name) == 0 || len(crSpec.IssuerRef.Kind) == 0 {
		el = append(el, field.Required(fldPath.Child("issuerRef"), "issuerRef name and kind must be specified"))
	}

	return el
}
