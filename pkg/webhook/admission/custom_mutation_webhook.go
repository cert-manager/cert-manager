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
	"encoding/json"
	"errors"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func NewCustomMutationWebhook(
	scheme *runtime.Scheme,
	mutationWebhook MutationInterface,
) *admission.Webhook {
	return &admission.Webhook{
		Handler: &mutator{
			decoder: &internalDecoder{
				scheme: scheme,
				codecs: serializer.NewCodecFactory(scheme),
			},
			scheme:          scheme,
			mutationWebhook: mutationWebhook,
		},
	}
}

type mutator struct {
	decoder         *internalDecoder
	scheme          *runtime.Scheme
	mutationWebhook MutationInterface
}

// Handle handles admission requests.
func (h *mutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	if h.decoder == nil {
		panic("decoder should never be nil")
	}

	// short-path
	if h.mutationWebhook == nil || !h.mutationWebhook.Handles(req.AdmissionRequest.Operation) {
		return admission.Allowed("")
	}

	// Always skip when a DELETE operation received in custom mutation handler.
	if req.Operation == admissionv1.Delete {
		return admission.Allowed("")
	}

	ctx = admission.NewContextWithRequest(ctx, req)

	// Get the object in the request
	obj, err := h.decoder.DecodeRaw(req.Object)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Default the object
	if err := h.mutationWebhook.Mutate(ctx, req.AdmissionRequest, obj); err != nil {
		var apiStatus apierrors.APIStatus
		if errors.As(err, &apiStatus) {
			status := apiStatus.Status()
			return admission.Response{
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: false,
					Result:  &status,
				},
			}
		}
		return admission.Denied(err.Error())
	}

	// Convert the object into the original version that was submitted to the webhook
	// before generating the patch.
	outputGroupVersioner := runtime.NewMultiGroupVersioner(schema.GroupVersion{Group: req.Kind.Group, Version: req.Kind.Version})
	finalObject, err := h.scheme.ConvertToVersion(obj, outputGroupVersioner)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	// Create the patch
	marshalled, err := json.Marshal(finalObject)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, marshalled)
}
