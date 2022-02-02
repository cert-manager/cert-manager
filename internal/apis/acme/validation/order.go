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
	old, ok := oldObj.(*cmacme.Order)
	new := newObj.(*cmacme.Order)
	// if oldObj is not set, the Update operation is always valid.
	if !ok || old == nil {
		return nil, nil
	}

	el := field.ErrorList{}
	el = append(el, ValidateOrderSpecUpdate(old.Spec, new.Spec, field.NewPath("spec"))...)
	el = append(el, ValidateOrderStatusUpdate(old.Status, new.Status, field.NewPath("status"))...)
	return el, nil
}

func ValidateOrder(a *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, []string) {
	return nil, nil
}

func ValidateOrderSpecUpdate(old, new cmacme.OrderSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if len(old.Request) > 0 && !bytes.Equal(old.Request, new.Request) {
		el = append(el, field.Forbidden(fldPath.Child("request"), "field is immutable once set"))
	}
	return el
}

func ValidateOrderStatusUpdate(old, new cmacme.OrderStatus, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	// once the order URL has been set, it cannot be changed
	if old.URL != "" && old.URL != new.URL {
		el = append(el, field.Forbidden(fldPath.Child("url"), "field is immutable once set"))
	}
	// once the FinalizeURL has been set, it cannot be changed
	if old.FinalizeURL != "" && old.FinalizeURL != new.FinalizeURL {
		el = append(el, field.Forbidden(fldPath.Child("finalizeURL"), "field is immutable once set"))
	}
	// once the Certificate has been issued, it cannot be changed
	if len(old.Certificate) > 0 && !bytes.Equal(old.Certificate, new.Certificate) {
		el = append(el, field.Forbidden(fldPath.Child("certificate"), "field is immutable once set"))
	}

	if len(old.Authorizations) > 0 {
		fldPath := fldPath.Child("authorizations")

		// once at least one Authorization has been inserted, no more can be added
		// or deleted from the Order
		if len(old.Authorizations) != len(new.Authorizations) {
			el = append(el, field.Forbidden(fldPath, "field is immutable once set"))
		}

		// here we know that len(old) == len(new), so we proceed to validate
		// the updates that the user requested on each Authorization.
		// fields on Authorization's cannot be changed after being set from
		// their zero value.
		for i := range old.Authorizations {
			fldPath := fldPath.Index(i)
			old := old.Authorizations[i]
			new := new.Authorizations[i]
			if old.URL != "" && old.URL != new.URL {
				el = append(el, field.Forbidden(fldPath.Child("url"), "field is immutable once set"))
			}
			if old.Identifier != "" && old.Identifier != new.Identifier {
				el = append(el, field.Forbidden(fldPath.Child("identifier"), "field is immutable once set"))
			}
			// don't allow the value of the Wildcard field to change unless the
			// old value is nil
			if old.Wildcard != nil && (new.Wildcard == nil || *old.Wildcard != *new.Wildcard) {
				el = append(el, field.Forbidden(fldPath.Child("wildcard"), "field is immutable once set"))
			}
			if old.InitialState != "" && (old.InitialState != new.InitialState) {
				el = append(el, field.Forbidden(fldPath.Child("initialState"), "field is immutable once set"))
			}

			if len(old.Challenges) > 0 {
				fldPath := fldPath.Child("challenges")
				if len(old.Challenges) != len(new.Challenges) {
					el = append(el, field.Forbidden(fldPath, "field is immutable once set"))
				}

				for i := range old.Challenges {
					fldPath := fldPath.Index(i)
					old := old.Challenges[i]
					new := new.Challenges[i]

					if old.URL != "" && old.URL != new.URL {
						el = append(el, field.Forbidden(fldPath.Child("url"), "field is immutable once set"))
					}
					if old.Type != "" && old.Type != new.Type {
						el = append(el, field.Forbidden(fldPath.Child("type"), "field is immutable once set"))
					}
					if old.Token != "" && old.Token != new.Token {
						el = append(el, field.Forbidden(fldPath.Child("token"), "field is immutable once set"))
					}
				}
			}
		}
	}

	return el
}
