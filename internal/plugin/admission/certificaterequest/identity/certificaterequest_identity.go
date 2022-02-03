/*
Copyright 2021 The cert-manager Authors.

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

package identity

import (
	"context"
	"fmt"
	"reflect"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/cert-manager/cert-manager/internal/apis/certmanager"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/pkg/webhook/admission"
)

const PluginName = "CertificateRequestIdentity"

type certificateRequestIdentity struct {
	*admission.Handler
}

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func() (admission.Interface, error) {
		return NewPlugin(), nil
	})
}

var _ admission.ValidationInterface = &certificateRequestIdentity{}
var _ admission.MutationInterface = &certificateRequestIdentity{}

func NewPlugin() admission.Interface {
	return &certificateRequestIdentity{
		Handler: admission.NewHandler(admissionv1.Create, admissionv1.Update),
	}
}

func (p *certificateRequestIdentity) Mutate(ctx context.Context, request admissionv1.AdmissionRequest, obj runtime.Object) error {
	// Only run this admission plugin for the certificaterequests/status sub-resource
	if request.RequestResource.Group != "cert-manager.io" ||
		request.RequestResource.Resource != "certificaterequests" ||
		request.Operation != admissionv1.Create {
		return nil
	}

	cr := obj.(*certmanager.CertificateRequest)
	cr.Spec.UID = request.UserInfo.UID
	cr.Spec.Username = request.UserInfo.Username
	cr.Spec.Groups = request.UserInfo.Groups
	cr.Spec.Extra = make(map[string][]string)
	for k, v := range request.UserInfo.Extra {
		cr.Spec.Extra[k] = v
	}

	return nil
}

func (p *certificateRequestIdentity) Validate(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) ([]string, error) {
	// Only run this admission plugin for CertificateRequest resources
	if request.RequestResource.Group != "cert-manager.io" ||
		request.RequestResource.Resource != "certificaterequests" {
		return nil, nil
	}

	// Cast the obj to a CertificateRequest
	cr, ok := obj.(*certmanager.CertificateRequest)
	if !ok {
		return nil, fmt.Errorf("internal error: object in admission request is not of type *certmanager.CertificateRequest")
	}

	switch request.Operation {
	case admissionv1.Create:
		return nil, validateCreate(request, cr)
	case admissionv1.Update:
		oldCR, ok := oldObj.(*certmanager.CertificateRequest)
		if !ok {
			return nil, fmt.Errorf("internal error: oldObject in admission request is not of type *certmanager.CertificateRequest")
		}
		return nil, validateUpdate(oldCR, cr)
	}

	return nil, fmt.Errorf("internal error: request operation has changed - this should never be possible")
}

func validateUpdate(oldCR *certmanager.CertificateRequest, cr *certmanager.CertificateRequest) error {
	fldPath := field.NewPath("spec")

	var el field.ErrorList
	if oldCR.Spec.UID != cr.Spec.UID {
		el = append(el, field.Forbidden(fldPath.Child("uid"), "uid identity cannot be changed once set"))
	}
	if oldCR.Spec.Username != cr.Spec.Username {
		el = append(el, field.Forbidden(fldPath.Child("username"), "username identity cannot be changed once set"))
	}
	if !util.EqualUnsorted(oldCR.Spec.Groups, cr.Spec.Groups) {
		el = append(el, field.Forbidden(fldPath.Child("groups"), "groups identity cannot be changed once set"))
	}
	if !reflect.DeepEqual(oldCR.Spec.Extra, cr.Spec.Extra) {
		el = append(el, field.Forbidden(fldPath.Child("extra"), "extra identity cannot be changed once set"))
	}
	return el.ToAggregate()
}

func validateCreate(request admissionv1.AdmissionRequest, cr *certmanager.CertificateRequest) error {
	fldPath := field.NewPath("spec")

	var el field.ErrorList
	if cr.Spec.UID != request.UserInfo.UID {
		el = append(el, field.Forbidden(fldPath.Child("uid"), "uid identity must be that of the requester"))
	}
	if cr.Spec.Username != request.UserInfo.Username {
		el = append(el, field.Forbidden(fldPath.Child("username"), "username identity must be that of the requester"))
	}
	if !util.EqualUnsorted(cr.Spec.Groups, request.UserInfo.Groups) {
		el = append(el, field.Forbidden(fldPath.Child("groups"), "groups identity must be that of the requester"))
	}
	if !extrasMatch(cr.Spec.Extra, request.UserInfo.Extra) {
		el = append(el, field.Forbidden(fldPath.Child("extra"), "extra identity must be that of the requester"))
	}
	return el.ToAggregate()
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
