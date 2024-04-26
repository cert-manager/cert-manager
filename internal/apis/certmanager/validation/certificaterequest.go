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
	"reflect"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmapi "github.com/cert-manager/cert-manager/internal/apis/certmanager"
	cmmeta "github.com/cert-manager/cert-manager/internal/apis/meta"
	"github.com/cert-manager/cert-manager/pkg/apis/acme"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapiv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

func ValidateCertificateRequest(a *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, []string) {
	cr := obj.(*cmapi.CertificateRequest)
	allErrs := ValidateCertificateRequestSpec(&cr.Spec, field.NewPath("spec"))
	allErrs = append(allErrs,
		ValidateCertificateRequestApprovalCondition(cr.Status.Conditions, field.NewPath("status", "conditions"))...)

	return allErrs, nil
}

func ValidateUpdateCertificateRequest(a *admissionv1.AdmissionRequest, oldObj, newObj runtime.Object) (field.ErrorList, []string) {
	oldCR, newCR := oldObj.(*cmapi.CertificateRequest), newObj.(*cmapi.CertificateRequest)

	var el field.ErrorList

	// Enforce that no cert-manager annotations may be modified after creation.
	// This is to prevent changing the request during processing resulting in
	// undefined behaviour, and breaking the concept of requests being made by a
	// single user.
	annotationField := field.NewPath("metadata", "annotations")
	el = append(el, validateCertificateRequestAnnotations(oldCR, newCR, annotationField)...)
	el = append(el, validateCertificateRequestAnnotations(newCR, oldCR, annotationField)...)
	el = append(el,
		ValidateUpdateCertificateRequestApprovalCondition(oldCR.Status.Conditions, newCR.Status.Conditions, field.NewPath("status", "conditions"))...)

	if !reflect.DeepEqual(oldCR.Spec, newCR.Spec) {
		el = append(el, field.Forbidden(field.NewPath("spec"), "cannot change spec after creation"))
	}

	return el, nil
}

func validateCertificateRequestAnnotations(objA, objB *cmapi.CertificateRequest, fieldPath *field.Path) field.ErrorList {
	var el field.ErrorList
	for k, v := range objA.Annotations {
		if strings.HasPrefix(k, certmanager.GroupName) ||
			strings.HasPrefix(k, acme.GroupName) {
			if vnew, ok := objB.Annotations[k]; !ok || v != vnew {
				el = append(el, field.Forbidden(fieldPath.Child(k), "cannot change cert-manager annotation after creation"))
			}
		}
	}

	return el
}

func ValidateCertificateRequestSpec(crSpec *cmapi.CertificateRequestSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	el = append(el, validateIssuerRef(crSpec.IssuerRef, fldPath)...)

	el = append(el, validateCertificateRequestSpecRequest(crSpec, fldPath)...)

	return el
}

func validateCertificateRequestSpecRequest(crSpec *cmapi.CertificateRequestSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	if len(crSpec.Request) == 0 {
		el = append(el, field.Required(fldPath.Child("request"), "must be specified"))
		return el
	}

	usages := make([]cmapiv1.KeyUsage, 0, len(crSpec.Usages))
	for _, usage := range crSpec.Usages {
		usages = append(usages, cmapiv1.KeyUsage(usage))
	}

	keyUsage, extKeyUsage, err := pki.KeyUsagesForCertificateOrCertificateRequest(usages, crSpec.IsCA)
	if err != nil {
		el = append(el, field.Invalid(fldPath.Child("usages"), crSpec.Usages, err.Error()))
		return el
	}

	_, err = pki.CertificateTemplateFromCSRPEM(
		crSpec.Request,
		pki.CertificateTemplateValidateAndOverrideBasicConstraints(crSpec.IsCA, nil),
		pki.CertificateTemplateValidateAndOverrideKeyUsages(keyUsage, extKeyUsage),
	)
	if err != nil {
		el = append(el, field.Invalid(fldPath.Child("request"), crSpec.Request, err.Error()))
		return el
	}

	return el
}

// ValidateCertificateRequestApprovalCondition will ensure that only a single
// 'Approved' or 'Denied' condition may exist, and that they are set to True.
func ValidateCertificateRequestApprovalCondition(crConds []cmapi.CertificateRequestCondition, fldPath *field.Path) field.ErrorList {
	var (
		approvedConditions []cmapi.CertificateRequestCondition
		deniedConditions   []cmapi.CertificateRequestCondition
		el                 = field.ErrorList{}
	)

	for _, cond := range crConds {
		if cond.Type == cmapi.CertificateRequestConditionApproved {
			approvedConditions = append(approvedConditions, cond)
		}

		if cond.Type == cmapi.CertificateRequestConditionDenied {
			deniedConditions = append(deniedConditions, cond)
		}
	}

	for _, condType := range []struct {
		condType cmapi.CertificateRequestConditionType
		found    []cmapi.CertificateRequestCondition
	}{
		{cmapi.CertificateRequestConditionApproved, approvedConditions},
		{cmapi.CertificateRequestConditionDenied, deniedConditions},
	} {
		if len(condType.found) == 0 {
			continue
		}

		if len(condType.found) > 1 {
			el = append(el, field.Forbidden(fldPath, fmt.Sprintf("multiple %q conditions present", condType.condType)))
			continue
		}

		first := condType.found[0]
		if first.Status != cmmeta.ConditionTrue {
			el = append(el, field.Invalid(fldPath.Child(string(first.Type)), first.Status,
				fmt.Sprintf("%q condition may only be set to True", condType.condType)))
			continue
		}
	}

	if len(deniedConditions) > 0 && len(approvedConditions) > 0 {
		el = append(el, field.Forbidden(fldPath, "both 'Denied' and 'Approved' conditions cannot coexist"))
	}

	return el
}

// ValidateUpdateCertificateRequestApprovalCondition will ensure that the
// 'Approved' and 'Denied' conditions may not be changed once set, i.e. if they
// exist, they are not modified in the updated resource. Also runs the base
// approval validation on the updated CertificateRequest conditions.
func ValidateUpdateCertificateRequestApprovalCondition(oldCRConds, newCRConds []cmapi.CertificateRequestCondition, fldPath *field.Path) field.ErrorList {
	var (
		el            = field.ErrorList{}
		oldCRDenied   = getCertificateRequestCondition(oldCRConds, cmapi.CertificateRequestConditionDenied)
		oldCRApproved = getCertificateRequestCondition(oldCRConds, cmapi.CertificateRequestConditionApproved)
	)

	// If the approval condition has been set, ensure it hasn't been modified.
	if oldCRApproved != nil && !reflect.DeepEqual(oldCRApproved,
		getCertificateRequestCondition(newCRConds, cmapi.CertificateRequestConditionApproved),
	) {
		el = append(el, field.Forbidden(fldPath, "'Approved' condition may not be modified once set"))
	}

	// If the denied condition has been set, ensure it hasn't been modified.
	if oldCRDenied != nil && !reflect.DeepEqual(oldCRDenied,
		getCertificateRequestCondition(newCRConds, cmapi.CertificateRequestConditionDenied),
	) {
		el = append(el, field.Forbidden(fldPath, "'Denied' condition may not be modified once set"))
	}

	return append(el, ValidateCertificateRequestApprovalCondition(newCRConds, fldPath)...)
}

func getCertificateRequestCondition(conds []cmapi.CertificateRequestCondition, conditionType cmapi.CertificateRequestConditionType) *cmapi.CertificateRequestCondition {
	for _, cond := range conds {
		if cond.Type == conditionType {
			return &cond
		}
	}
	return nil
}
