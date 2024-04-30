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
	"bytes"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmacme "github.com/cert-manager/cert-manager/internal/apis/acme"
)

func ValidateOrderUpdate(a *admissionv1.AdmissionRequest, oldObj, newObj runtime.Object) (field.ErrorList, []string) {
	oldOrder, ok := oldObj.(*cmacme.Order)
	newOrder := newObj.(*cmacme.Order)
	// if oldObj is not set, the Update operation is always valid.
	if !ok || oldOrder == nil {
		return nil, nil
	}

	el := field.ErrorList{}
	el = append(el, ValidateOrderSpecUpdate(oldOrder.Spec, newOrder.Spec, field.NewPath("spec"))...)
	el = append(el, ValidateOrderStatusUpdate(oldOrder.Status, newOrder.Status, field.NewPath("status"))...)
	return el, nil
}

func ValidateOrder(a *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, []string) {
	return nil, nil
}

func ValidateOrderSpecUpdate(oldOrder, newOrder cmacme.OrderSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if len(oldOrder.Request) > 0 && !bytes.Equal(oldOrder.Request, newOrder.Request) {
		el = append(el, field.Forbidden(fldPath.Child("request"), "field is immutable once set"))
	}
	return el
}

func ValidateOrderStatusUpdate(oldStatus, newStatus cmacme.OrderStatus, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	// once the order URL has been set, it cannot be changed
	if oldStatus.URL != "" && oldStatus.URL != newStatus.URL {
		el = append(el, field.Forbidden(fldPath.Child("url"), "field is immutable once set"))
	}
	// once the FinalizeURL has been set, it cannot be changed
	if oldStatus.FinalizeURL != "" && oldStatus.FinalizeURL != newStatus.FinalizeURL {
		el = append(el, field.Forbidden(fldPath.Child("finalizeURL"), "field is immutable once set"))
	}
	// once the Certificate has been issued, it cannot be changed
	if len(oldStatus.Certificate) > 0 && !bytes.Equal(oldStatus.Certificate, newStatus.Certificate) {
		el = append(el, field.Forbidden(fldPath.Child("certificate"), "field is immutable once set"))
	}

	if len(oldStatus.Authorizations) > 0 {
		fldPath := fldPath.Child("authorizations")

		// once at least one Authorization has been inserted, no more can be added
		// or deleted from the Order
		if len(oldStatus.Authorizations) != len(newStatus.Authorizations) {
			el = append(el, field.Forbidden(fldPath, "field is immutable once set"))
		}

		// here we know that len(old) == len(new), so we proceed to validate
		// the updates that the user requested on each Authorization.
		// fields on Authorization's cannot be changed after being set from
		// their zero value.
		for i := range oldStatus.Authorizations {
			fldPath := fldPath.Index(i)
			oldAuthz := oldStatus.Authorizations[i]
			newAuthz := newStatus.Authorizations[i]
			if oldAuthz.URL != "" && oldAuthz.URL != newAuthz.URL {
				el = append(el, field.Forbidden(fldPath.Child("url"), "field is immutable once set"))
			}
			if oldAuthz.Identifier != "" && oldAuthz.Identifier != newAuthz.Identifier {
				el = append(el, field.Forbidden(fldPath.Child("identifier"), "field is immutable once set"))
			}
			// don't allow the value of the Wildcard field to change unless the
			// old value is nil
			if oldAuthz.Wildcard != nil && (newAuthz.Wildcard == nil || *oldAuthz.Wildcard != *newAuthz.Wildcard) {
				el = append(el, field.Forbidden(fldPath.Child("wildcard"), "field is immutable once set"))
			}
			if oldAuthz.InitialState != "" && (oldAuthz.InitialState != newAuthz.InitialState) {
				el = append(el, field.Forbidden(fldPath.Child("initialState"), "field is immutable once set"))
			}

			if len(oldAuthz.Challenges) > 0 {
				fldPath := fldPath.Child("challenges")
				if len(oldAuthz.Challenges) != len(newAuthz.Challenges) {
					el = append(el, field.Forbidden(fldPath, "field is immutable once set"))
				}

				for i := range oldAuthz.Challenges {
					fldPath := fldPath.Index(i)
					oldChallenge := oldAuthz.Challenges[i]
					newChallenge := newAuthz.Challenges[i]

					if oldChallenge.URL != "" && oldChallenge.URL != newChallenge.URL {
						el = append(el, field.Forbidden(fldPath.Child("url"), "field is immutable once set"))
					}
					if oldChallenge.Type != "" && oldChallenge.Type != newChallenge.Type {
						el = append(el, field.Forbidden(fldPath.Child("type"), "field is immutable once set"))
					}
					if oldChallenge.Token != "" && oldChallenge.Token != newChallenge.Token {
						el = append(el, field.Forbidden(fldPath.Child("token"), "field is immutable once set"))
					}
				}
			}
		}
	}

	return el
}
