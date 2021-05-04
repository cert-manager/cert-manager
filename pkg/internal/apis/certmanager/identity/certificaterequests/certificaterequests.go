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

// Package certificaterequests populates and enforces identity on
// CertificateRequest resources.
package certificaterequests

import (
	"reflect"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/jetstack/cert-manager/pkg/internal/api/validation"
	cmapi "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
	"github.com/jetstack/cert-manager/pkg/util"
)

func ValidateCreate(req *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, validation.WarningList) {
	cr := obj.(*cmapi.CertificateRequest)
	fldPath := field.NewPath("spec")

	var el field.ErrorList
	if cr.Spec.UID != req.UserInfo.UID {
		el = append(el, field.Forbidden(fldPath.Child("uid"), "uid identity must be that of the requester"))
	}
	if cr.Spec.Username != req.UserInfo.Username {
		el = append(el, field.Forbidden(fldPath.Child("username"), "username identity must be that of the requester"))
	}
	if !util.EqualUnsorted(cr.Spec.Groups, req.UserInfo.Groups) {
		el = append(el, field.Forbidden(fldPath.Child("groups"), "groups identity must be that of the requester"))
	}
	if !extrasMatch(cr.Spec.Extra, req.UserInfo.Extra) {
		el = append(el, field.Forbidden(fldPath.Child("extra"), "extra identity must be that of the requester"))
	}

	return el, nil
}

func extrasMatch(crExtra map[string][]string, reqExtra map[string]authenticationv1.ExtraValue) bool {
	if len(crExtra) != len(reqExtra) {
		return false
	}

	for k, v := range crExtra {
		reqv, ok := reqExtra[k]
		if !ok {
			return false
		}

		if !util.EqualUnsorted(v, reqv) {
			return false
		}
	}

	return true
}

func ValidateUpdate(_ *admissionv1.AdmissionRequest, oldObj, newObj runtime.Object) (field.ErrorList, validation.WarningList) {
	oldCR, newCR := oldObj.(*cmapi.CertificateRequest), newObj.(*cmapi.CertificateRequest)
	fldPath := field.NewPath("spec")

	var el field.ErrorList
	if oldCR.Spec.UID != newCR.Spec.UID {
		el = append(el, field.Forbidden(fldPath.Child("uid"), "uid identity cannot be changed once set"))
	}
	if oldCR.Spec.Username != newCR.Spec.Username {
		el = append(el, field.Forbidden(fldPath.Child("username"), "username identity cannot be changed once set"))
	}
	if !util.EqualUnsorted(oldCR.Spec.Groups, newCR.Spec.Groups) {
		el = append(el, field.Forbidden(fldPath.Child("groups"), "groups identity cannot be changed once set"))
	}
	if !reflect.DeepEqual(oldCR.Spec.Extra, newCR.Spec.Extra) {
		el = append(el, field.Forbidden(fldPath.Child("extra"), "extra identity cannot be changed once set"))
	}

	return el, nil
}

func MutateCreate(req *admissionv1.AdmissionRequest, obj runtime.Object) {
	cr := obj.(*cmapi.CertificateRequest)
	userInfo := req.DeepCopy().UserInfo

	cr.Spec.UID = userInfo.UID
	cr.Spec.Username = userInfo.Username
	cr.Spec.Groups = userInfo.Groups
	cr.Spec.Extra = make(map[string][]string)
	for k, v := range userInfo.Extra {
		cr.Spec.Extra[k] = v
	}
}

func MutateUpdate(_ *admissionv1.AdmissionRequest, _, _ runtime.Object) {
}
