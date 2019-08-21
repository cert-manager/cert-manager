/*
Copyright 2019 The Jetstack cert-manager contributors.

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
	"fmt"
	"net/http"

	"github.com/go-logr/logr"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/rest"
)

type funcBackedValidator struct {
	log         logr.Logger
	groupName   string
	decoder     runtime.Decoder
	validations map[schema.GroupVersionKind]ValidationFunc
}

func NewFuncBackedValidator(log logr.Logger, groupName string, scheme *runtime.Scheme, fns map[schema.GroupVersionKind]ValidationFunc) *funcBackedValidator {
	factory := serializer.NewCodecFactory(scheme)
	return &funcBackedValidator{
		log:       log,
		groupName: groupName,
		// TODO: switch to using UniversalDecoder and make validation functions
		//       run against the internal apiversion
		decoder:     factory.UniversalDeserializer(),
		validations: fns,
	}
}

type ValidationFunc func(runtime.Object) field.ErrorList

func (c *funcBackedValidator) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	return nil
}

func (c *funcBackedValidator) ValidatingResource() (plural schema.GroupVersionResource, singular string) {
	gv := admissionv1beta1.SchemeGroupVersion
	gv.Group = c.groupName
	return gv.WithResource("validations"), "validation"
}

func (c *funcBackedValidator) Validate(admissionSpec *admissionv1beta1.AdmissionRequest) *admissionv1beta1.AdmissionResponse {
	status := &admissionv1beta1.AdmissionResponse{}

	obj, gvk, err := c.decoder.Decode(admissionSpec.Object.Raw, nil, nil)
	if err != nil {
		status.Allowed = false
		status.Result = &metav1.Status{
			Status: metav1.StatusFailure, Code: http.StatusBadRequest, Reason: metav1.StatusReasonBadRequest,
			Message: err.Error(),
		}
		return status
	}

	validate, ok := c.validations[*gvk]
	if !ok {
		status.Allowed = false
		status.Result = &metav1.Status{
			Status: metav1.StatusFailure, Code: http.StatusInternalServerError, Reason: metav1.StatusReasonInternalError,
			Message: fmt.Sprintf("No validation function registered for GVK: %v", gvk.String()),
		}
		return status
	}

	err = validate(obj).ToAggregate()
	if err != nil {
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
