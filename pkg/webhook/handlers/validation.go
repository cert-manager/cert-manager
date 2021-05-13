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
	"net/http"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"

	"github.com/jetstack/cert-manager/pkg/internal/api/validation"
	"github.com/jetstack/cert-manager/pkg/internal/apis/certmanager/validation/plugins"
)

type registryBackedValidator struct {
	log      logr.Logger
	decoder  runtime.Decoder
	registry *validation.Registry

	plugins []plugins.Plugin
}

func NewRegistryBackedValidator(log logr.Logger, scheme *runtime.Scheme, registry *validation.Registry) *registryBackedValidator {
	factory := serializer.NewCodecFactory(scheme)
	return &registryBackedValidator{
		log:      log,
		decoder:  factory.UniversalDecoder(),
		registry: registry,
		plugins:  plugins.All(scheme),
	}
}

func (r *registryBackedValidator) InitPlugins(client kubernetes.Interface) {
	for _, plugin := range r.plugins {
		plugin.Init(client)
	}
}

func (r *registryBackedValidator) Validate(ctx context.Context, admissionSpec *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	status := &admissionv1.AdmissionResponse{}
	status.UID = admissionSpec.UID

	// decode new version of object
	obj, _, err := r.decoder.Decode(admissionSpec.Object.Raw, nil, nil)
	if err != nil {
		status.Allowed = false
		status.Result = &metav1.Status{
			Status: metav1.StatusFailure, Code: http.StatusBadRequest, Reason: metav1.StatusReasonBadRequest,
			Message: err.Error(),
		}
		return status
	}

	// attempt to decode old object
	var oldObj runtime.Object
	if len(admissionSpec.OldObject.Raw) > 0 {
		oldObj, _, err = r.decoder.Decode(admissionSpec.OldObject.Raw, nil, nil)
		if err != nil {
			status.Allowed = false
			status.Result = &metav1.Status{
				Status: metav1.StatusFailure, Code: http.StatusBadRequest, Reason: metav1.StatusReasonBadRequest,
				Message: err.Error(),
			}
			return status
		}
	}

	// RequestKind field is only present from Kubernetes 1.15 onwards, so
	// use the regular 'kind' if RequestKind is not present
	gvk := schema.GroupVersionKind{
		Group:   admissionSpec.Kind.Group,
		Version: admissionSpec.Kind.Version,
		Kind:    admissionSpec.Kind.Kind,
	}
	if admissionSpec.RequestKind != nil {
		gvk = schema.GroupVersionKind{
			Group:   admissionSpec.RequestKind.Group,
			Version: admissionSpec.RequestKind.Version,
			Kind:    admissionSpec.RequestKind.Kind,
		}
	}
	errs := field.ErrorList{}
	var warnings validation.WarningList

	if admissionSpec.Operation == admissionv1.Create {
		// perform validation on new version of resource
		e, w := r.registry.Validate(admissionSpec, obj, gvk)
		errs, warnings = append(errs, e...), append(warnings, w...)
	} else if admissionSpec.Operation == admissionv1.Update {
		// perform update validation on resource
		e, w := r.registry.ValidateUpdate(admissionSpec, oldObj, obj, gvk)
		errs, warnings = append(errs, e...), append(warnings, w...)
	}

	// TODO: implement warnings for Plugin interface
	// If no validation errors occurred, perform plugin checks.
	if len(errs) == 0 {
		for _, plugin := range r.plugins {
			if err := plugin.Validate(ctx, admissionSpec, oldObj, obj); err != nil {
				errs = append(errs, err)
			}
		}
	}

	status.Warnings = warnings

	// return with allowed = false if any errors occurred
	if err := errs.ToAggregate(); err != nil {
		status.Allowed = false
		status.Result = &metav1.Status{
			Status: metav1.StatusFailure, Code: http.StatusNotAcceptable, Reason: metav1.StatusReasonNotAcceptable,
			Message: err.Error(),
		}
		return status
	}

	status.Allowed = true
	return status
}
