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

package handlers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/jetstack/cert-manager/pkg/internal/api/mutation"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

type RegistryBackedMutator struct {
	log      logr.Logger
	decoder  runtime.Decoder
	registry *mutation.Registry
}

func NewRegistryBackedMutator(log logr.Logger, scheme *runtime.Scheme, registry *mutation.Registry) *RegistryBackedMutator {
	factory := serializer.NewCodecFactory(scheme)
	return &RegistryBackedMutator{
		log:      log,
		decoder:  factory.UniversalDecoder(),
		registry: registry,
	}
}

func (c *RegistryBackedMutator) Mutate(_ context.Context, admissionSpec *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	status := &admissionv1.AdmissionResponse{}
	status.UID = admissionSpec.UID

	// Generate a patch from the appropriate functions installed in the mutation registry
	patch, err := c.registry.Mutate(admissionSpec)
	if err != nil {
		status.Result = &metav1.Status{
			Status: metav1.StatusFailure, Code: http.StatusInternalServerError, Reason: metav1.StatusReasonInternalError,
			Message: fmt.Sprintf("Failed to mutate object: %v", err.Error()),
		}
		return status
	}

	// set the AdmissionReview status
	jsonPatchType := admissionv1.PatchTypeJSONPatch
	status.Patch = patch
	status.PatchType = &jsonPatchType
	status.Allowed = true

	c.log.V(logf.DebugLevel).Info("generated patch", "patch", string(patch))

	return status
}
