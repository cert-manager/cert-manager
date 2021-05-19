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

// Package validation allows a caller to automatically register, lookup and
// call API validation functions.
// It is similar to runtime.Scheme and is designed to make writing and
// consuming API validation functions easier.
package validation

import (
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Registry is used to store and lookup references to validation functions for
// given Kubernetes API types.
type Registry struct {
	scheme                 *runtime.Scheme
	validateRegister       map[schema.GroupVersionKind]ValidateFunc
	validateUpdateRegister map[schema.GroupVersionKind]ValidateUpdateFunc
}

// ValidateFunc is a function type that implements validation for an admission
// request associated with a creation of an object of a particular type.
type ValidateFunc func(req *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, WarningList)

// ValidateUpdateFunc is a function type that implements validation for an
// admission request associated with update of an object of a particular type.
type ValidateUpdateFunc func(req *admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (field.ErrorList, WarningList)

// NewRegistry creates a new empty registry, backed by the provided Scheme.
func NewRegistry(scheme *runtime.Scheme) *Registry {
	return &Registry{
		scheme:                 scheme,
		validateRegister:       make(map[schema.GroupVersionKind]ValidateFunc),
		validateUpdateRegister: make(map[schema.GroupVersionKind]ValidateUpdateFunc),
	}
}

// AddValidateFunc will add a new validation function to the register.
// The function will be run whenever Validate is called with a requestVersion
// set to any recognised GroupVersionKinds for this object.
// If obj is part of an internal API version, the validation function will be
// called on all calls to Validate regardless of version.
// If obj cannot be recognised using the registry's scheme, an error will be
// returned.
func (r *Registry) AddValidateFunc(obj runtime.Object, fn ValidateFunc) error {
	gvks, _, err := r.scheme.ObjectKinds(obj)
	if err != nil {
		return err
	}

	for _, gvk := range gvks {
		r.appendValidate(gvk, fn)
	}

	return nil
}

// AddValidateUpdateFunc will add a new validation function to the register.
// The function will be run whenever ValidateUpdate is called with a
// requestVersion set to any recognised GroupVersionKinds for this object.
// If obj is part of an internal API version, the validation function will be
// called on all calls to Validate regardless of version.
// If obj cannot be recognised using the registry's scheme, an error will be
// returned.
func (r *Registry) AddValidateUpdateFunc(obj runtime.Object, fn ValidateUpdateFunc) error {
	gvks, _, err := r.scheme.ObjectKinds(obj)
	if err != nil {
		return err
	}

	for _, gvk := range gvks {
		r.appendValidateUpdate(gvk, fn)
	}

	return nil
}

// Validate will run all validation functions registered for the given object.
// If the passed obj is *not* of the same version as the provided
// requestVersion, the registry will attempt to convert the object before
// calling the validation functions.
// Any validation functions registered for the objects internal API version
// will be run against the object regardless of version.
func (r *Registry) Validate(req *admissionv1.AdmissionRequest, obj runtime.Object, requestVersion schema.GroupVersionKind) (field.ErrorList, WarningList) {
	versioned, internal := r.lookupValidateFuncs(requestVersion)
	if versioned == nil && internal == nil {
		return nil, nil
	}

	targetObj, internalObj, err := r.convert(obj, requestVersion)
	if err != nil {
		return internalError(err), nil
	}

	el := field.ErrorList{}
	warnings := WarningList{}
	if versioned != nil {
		e, w := versioned(req, targetObj)
		el, warnings = append(el, e...), append(warnings, w...)
	}
	if internal != nil {
		e, w := internal(req, internalObj)
		el, warnings = append(el, e...), append(warnings, w...)
	}

	return el, warnings
}

// ValidateUpdate will run all update validation functions registered for the
// given object.
// If the passed objects are *not* of the same version as the provided
// requestVersion, the registry will attempt to convert the objects before
// calling the validation functions.
// Any validation functions registered for the objects internal API version
// will be run against the object regardless of version.
func (r *Registry) ValidateUpdate(req *admissionv1.AdmissionRequest, oldObj, obj runtime.Object, requestVersion schema.GroupVersionKind) (field.ErrorList, []string) {
	versioned, internal := r.lookupValidateUpdateFuncs(requestVersion)
	if versioned == nil && internal == nil {
		return nil, nil
	}

	targetOldObj, internalOldObj, err := r.convert(oldObj, requestVersion)
	if err != nil {
		return internalError(err), nil
	}

	targetObj, internalObj, err := r.convert(obj, requestVersion)
	if err != nil {
		return internalError(err), nil
	}

	el := field.ErrorList{}
	warnings := WarningList{}
	if versioned != nil {
		e, w := versioned(req, targetOldObj, targetObj)
		el, warnings = append(el, e...), append(warnings, w...)
	}
	if internal != nil {
		e, w := internal(req, internalOldObj, internalObj)
		el, warnings = append(el, e...), append(warnings, w...)
	}

	return el, warnings
}

func (r *Registry) lookupValidateFuncs(gvk schema.GroupVersionKind) (versioned ValidateFunc, internal ValidateFunc) {
	versioned = r.validateRegister[gvk]
	gvk.Version = runtime.APIVersionInternal
	internal = r.validateRegister[gvk]
	return versioned, internal
}

func (r *Registry) lookupValidateUpdateFuncs(gvk schema.GroupVersionKind) (versioned ValidateUpdateFunc, internal ValidateUpdateFunc) {
	versioned = r.validateUpdateRegister[gvk]
	gvk.Version = runtime.APIVersionInternal
	internal = r.validateUpdateRegister[gvk]
	return versioned, internal
}

func (r *Registry) appendValidate(gvk schema.GroupVersionKind, fn ValidateFunc) {
	existing, ok := r.validateRegister[gvk]
	if !ok {
		r.validateRegister[gvk] = fn
		return
	}

	// If a ValidateFunc for GVK already exists, build a new ValidateFunc that
	// will return both the results of the new and old ValidateFunc.
	r.validateRegister[gvk] = func(req *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, WarningList) {
		e, w := existing(req, obj)
		newE, newW := fn(req, obj)
		return append(e, newE...), append(w, newW...)
	}
}

func (r *Registry) appendValidateUpdate(gvk schema.GroupVersionKind, fn ValidateUpdateFunc) {
	existing, ok := r.validateUpdateRegister[gvk]
	if !ok {
		r.validateUpdateRegister[gvk] = fn
		return
	}

	// If a ValidateUpdateFunc for GVK already exists, build a new
	// ValidateUpdateFunc that will return both the results of the new and old
	// ValidateUpdateFunc.
	r.validateUpdateRegister[gvk] = func(req *admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (field.ErrorList, WarningList) {
		e, w := existing(req, oldObj, obj)
		newE, newW := fn(req, oldObj, obj)
		return append(e, newE...), append(w, newW...)
	}
}

// convert will convert the given obj into the requestVersion as well as
// returning the internal representation of the object.
func (r *Registry) convert(obj runtime.Object, requestVersion schema.GroupVersionKind) (targetObj, internalObj runtime.Object, err error) {
	// create a new object in the desired version
	targetObj, err = r.scheme.New(requestVersion)
	if err != nil {
		return nil, nil, err
	}
	// create a new object in the 'internal' version
	internalVersion := requestVersion
	internalVersion.Version = runtime.APIVersionInternal
	internalObj, err = r.scheme.New(internalVersion)
	if err != nil {
		return nil, nil, err
	}

	// convert the obj into the internalVersion first
	if err := r.scheme.Convert(obj, internalObj, nil); err != nil {
		return nil, nil, err
	}

	// convert the internalObj into the requestVersion
	if err := r.scheme.Convert(internalObj, targetObj, nil); err != nil {
		return nil, nil, err
	}

	return targetObj, internalObj, nil
}

func internalError(err error) field.ErrorList {
	return field.ErrorList{field.InternalError(nil, err)}
}
