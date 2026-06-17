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
	"reflect"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmacme "github.com/cert-manager/cert-manager/internal/apis/acme"
)

func ValidateChallengeUpdate(a *admissionv1.AdmissionRequest, oldObj, newObj runtime.Object) (field.ErrorList, []string) {
	oldChallenge, ok := oldObj.(*cmacme.Challenge)
	newChallenge := newObj.(*cmacme.Challenge)
	// if oldObj is not set, the Update operation is always valid.
	if !ok || oldChallenge == nil {
		return nil, nil
	}

	el := field.ErrorList{}
	if !reflect.DeepEqual(oldChallenge.Spec, newChallenge.Spec) {
		el = append(el, field.Forbidden(field.NewPath("spec"), "challenge spec is immutable after creation"))
	}
	return el, nil
}

func ValidateChallenge(a *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, []string) {
	return nil, nil
}
