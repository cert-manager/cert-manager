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
	"net/http"

	"github.com/go-logr/logr"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

type Validator interface {
	// NewObject should return the runtime.Object that should be decoded into
	// before validating the resource.
	NewObject() runtime.Object

	// Validate will validate the given resource
	Validate(runtime.Object) field.ErrorList

	// ValidateUpdate will validate the given resource for an update
	ValidateUpdate(old, new runtime.Object) field.ErrorList
}

type validatorFunc struct {
	obj            runtime.Object
	validate       func(runtime.Object) field.ErrorList
	validateUpdate func(runtime.Object, runtime.Object) field.ErrorList
}

var _ Validator = &validatorFunc{}

func (v *validatorFunc) NewObject() runtime.Object {
	return v.obj.DeepCopyObject()
}

func (v *validatorFunc) Validate(obj runtime.Object) field.ErrorList {
	if v.validate == nil {
		return nil
	}
	return v.validate(obj)
}

func (v *validatorFunc) ValidateUpdate(old, new runtime.Object) field.ErrorList {
	if v.validateUpdate == nil {
		return nil
	}
	return v.validateUpdate(old, new)
}

func ValidatorFunc(obj runtime.Object, validate func(runtime.Object) field.ErrorList, validateUpdate func(runtime.Object, runtime.Object) field.ErrorList) Validator {
	return &validatorFunc{
		obj:            obj,
		validate:       validate,
		validateUpdate: validateUpdate,
	}
}

type funcBackedValidator struct {
	log        logr.Logger
	decoder    runtime.Decoder
	validators map[schema.GroupKind]Validator
}

func NewFuncBackedValidator(log logr.Logger, scheme *runtime.Scheme, validators map[schema.GroupKind]Validator) *funcBackedValidator {
	factory := serializer.NewCodecFactory(scheme)
	return &funcBackedValidator{
		log:        log,
		decoder:    factory.UniversalDecoder(),
		validators: validators,
	}
}

type ValidationFunc func(obj runtime.Object) field.ErrorList
type UpdateValidationFunc func(old, new runtime.Object) field.ErrorList

func (c *funcBackedValidator) Validate(admissionSpec *admissionv1beta1.AdmissionRequest) *admissionv1beta1.AdmissionResponse {
	status := &admissionv1beta1.AdmissionResponse{}
	status.UID = admissionSpec.UID

	gk := schema.GroupKind{Group: admissionSpec.Kind.Group, Kind: admissionSpec.Kind.Kind}
	validator := c.validators[gk]

	obj := validator.NewObject()
	// decode new version of object
	_, _, err := c.decoder.Decode(admissionSpec.Object.Raw, nil, obj)
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
		oldObj = validator.NewObject()
		_, _, err = c.decoder.Decode(admissionSpec.OldObject.Raw, nil, oldObj)
		if err != nil {
			status.Allowed = false
			status.Result = &metav1.Status{
				Status: metav1.StatusFailure, Code: http.StatusBadRequest, Reason: metav1.StatusReasonBadRequest,
				Message: err.Error(),
			}
			return status
		}
	}

	errs := field.ErrorList{}
	// perform validation on new version of resource
	errs = append(errs, validator.Validate(obj)...)
	// perform update validation on resource
	errs = append(errs, validator.ValidateUpdate(oldObj, obj)...)

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
