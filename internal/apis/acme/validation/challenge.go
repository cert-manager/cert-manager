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
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmacme "github.com/cert-manager/cert-manager/internal/apis/acme"
	"github.com/cert-manager/cert-manager/pkg/apis/acme"
)

func ValidateChallengeUpdate(a *admissionv1.AdmissionRequest, oldObj, newObj runtime.Object) (field.ErrorList, []string) {
	oldChallenge, ok := oldObj.(*cmacme.Challenge)
	newChallenge := newObj.(*cmacme.Challenge)
	// if oldObj is not set, the Update operation is always valid.
	if !ok || oldChallenge == nil {
		return nil, nil
	}

	var el field.ErrorList
	if !reflect.DeepEqual(oldChallenge.Spec, newChallenge.Spec) {
		el = append(el, field.Forbidden(field.NewPath("spec"), "challenge spec is immutable after creation"))
	}
	return el, nil
}

// ValidateChallenge rejects Challenge resources that lack a controller owner
// reference to an Order. This is defence in depth against Challenge smuggling
// (GHSA-8rvj-mm4h-c258); it is not a hard security boundary because owner
// references are not access-controlled in Kubernetes.
func ValidateChallenge(a *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, []string) {
	ch := obj.(*cmacme.Challenge)
	var el field.ErrorList

	if !hasOrderControllerOwner(ch) {
		el = append(el, field.Invalid(
			field.NewPath("metadata", "ownerReferences"),
			ch.GetOwnerReferences(),
			"challenge resources must be owned by an Order resource",
		))
	}

	return el, nil
}

func hasOrderControllerOwner(ch metav1.Object) bool {
	controllerRef := metav1.GetControllerOfNoCopy(ch)
	if controllerRef == nil {
		return false
	}

	return controllerRef.Kind == "Order" &&
		strings.HasPrefix(controllerRef.APIVersion, acme.GroupName+"/")
}
