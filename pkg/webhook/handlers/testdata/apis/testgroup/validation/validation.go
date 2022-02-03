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

	"github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup"
	v1 "github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/v1"
)

func ValidateTestType(_ *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, []string) {
	testType := obj.(*testgroup.TestType)
	el := field.ErrorList{}
	if testType.TestField == v1.TestFieldValueNotAllowed {
		el = append(el, field.Invalid(field.NewPath("testField"), testType.TestField, "invalid value"))
	}
	return el, nil
}

func ValidateTestTypeUpdate(_ *admissionv1.AdmissionRequest, oldObj, newObj runtime.Object) (field.ErrorList, []string) {
	old, ok := oldObj.(*testgroup.TestType)
	new := newObj.(*testgroup.TestType)
	// if oldObj is not set, the Update operation is always valid.
	if !ok || old == nil {
		return nil, nil
	}
	el := field.ErrorList{}
	if old.TestFieldImmutable != "" && old.TestFieldImmutable != new.TestFieldImmutable {
		el = append(el, field.Forbidden(field.NewPath("testFieldImmutable"), "field is immutable once set"))
	}
	return el, nil
}
