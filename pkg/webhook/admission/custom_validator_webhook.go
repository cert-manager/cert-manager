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

package admission

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func NewCustomValidationWebhook(
	scheme *runtime.Scheme,
	validationWebhook ValidationInterface,
) *admission.Webhook {
	return &admission.Webhook{
		Handler: &validator{
			decoder: &internalDecoder{
				scheme: scheme,
				codecs: serializer.NewCodecFactory(scheme),
			},
			validationWebhook: validationWebhook,
		},
	}
}

type validator struct {
	decoder           *internalDecoder
	validationWebhook ValidationInterface
}

// Handle handles admission requests.
func (h *validator) Handle(ctx context.Context, req admission.Request) admission.Response {
	if h.decoder == nil {
		panic("decoder should never be nil")
	}

	// short-path
	if h.validationWebhook == nil || !h.validationWebhook.Handles(req.AdmissionRequest.Operation) {
		return admission.Allowed("")
	}

	ctx = admission.NewContextWithRequest(ctx, req)
	gvk := schema.GroupVersionKind{
		Group:   req.Kind.Group,
		Version: req.Kind.Version,
		Kind:    req.Kind.Kind,
	}

	var obj runtime.Object
	var oldObj runtime.Object
	var err error
	var warnings []string

	switch req.Operation {
	case admissionv1.Connect:
		// No validation for connect requests.
		// TODO(vincepri): Should we validate CONNECT requests? In what cases?
	case admissionv1.Create:
		if obj, err = h.decoder.DecodeRaw(req.Object, gvk); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}

		warnings, err = h.validationWebhook.Validate(ctx, req.AdmissionRequest, nil, obj)
	case admissionv1.Update:
		if obj, err = h.decoder.DecodeRaw(req.Object, gvk); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}
		if oldObj, err = h.decoder.DecodeRaw(req.OldObject, gvk); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}

		warnings, err = h.validationWebhook.Validate(ctx, req.AdmissionRequest, oldObj, obj)
	case admissionv1.Delete:
		// In reference to PR: https://github.com/kubernetes/kubernetes/pull/76346
		// OldObject contains the object being deleted
		if oldObj, err = h.decoder.DecodeRaw(req.OldObject, gvk); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}

		warnings, err = h.validationWebhook.Validate(ctx, req.AdmissionRequest, oldObj, nil)
	default:
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("unknown operation %q", req.Operation))
	}

	// Check the error message first.
	if err != nil {
		var apiStatus apierrors.APIStatus
		if errors.As(err, &apiStatus) {
			status := apiStatus.Status()
			return admission.Response{
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: false,
					Result:  &status,
				},
			}.WithWarnings(warnings...)
		}
		return admission.Denied(err.Error()).WithWarnings(warnings...)
	}

	// Return allowed if everything succeeded.
	return admission.Allowed("").WithWarnings(warnings...)
}
