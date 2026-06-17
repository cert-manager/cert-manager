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
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmapi "github.com/cert-manager/cert-manager/internal/apis/certmanager"
)

// Validation functions for cert-manager ClusterIssuer types.

func ValidateClusterIssuer(a *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, []string) {
	iss := obj.(*cmapi.ClusterIssuer)
	allErrs, warnings := ValidateIssuerSpec(&iss.Spec, field.NewPath("spec"))
	return allErrs, warnings
}

func ValidateUpdateClusterIssuer(a *admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (field.ErrorList, []string) {
	iss := obj.(*cmapi.ClusterIssuer)
	allErrs, warnings := ValidateIssuerSpec(&iss.Spec, field.NewPath("spec"))
	return allErrs, warnings
}
