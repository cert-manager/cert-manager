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
	"errors"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"

	authzclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

// Registry is used to store and lookup references to validation functions for
// given Kubernetes API types.
type Registry struct {
	scheme                      *runtime.Scheme
	validateRegister            map[schema.GroupVersionKind]ValidateFunc
	validateUpdateRegister      map[schema.GroupVersionKind]ValidateUpdateFunc
	subjectAccessReviewRegister map[schema.GroupVersionKind]SubjectAccessReviewFunc

	sarclient authzclient.SubjectAccessReviewInterface
}

type ValidateFunc func(req *admissionv1.AdmissionRequest, obj runtime.Object) field.ErrorList
type ValidateUpdateFunc func(req *admissionv1.AdmissionRequest, oldObj, obj runtime.Object) field.ErrorList
type SubjectAccessReviewFunc func(client authzclient.SubjectAccessReviewInterface, req *admissionv1.AdmissionRequest, oldObj, obj runtime.Object) field.ErrorList

// NewRegistry creates a new empty registry, backed by the provided Scheme.
func NewRegistry(scheme *runtime.Scheme) *Registry {
	return &Registry{
		scheme:                      scheme,
		validateRegister:            make(map[schema.GroupVersionKind]ValidateFunc),
		validateUpdateRegister:      make(map[schema.GroupVersionKind]ValidateUpdateFunc),
		subjectAccessReviewRegister: make(map[schema.GroupVersionKind]SubjectAccessReviewFunc),
	}
}

func (r *Registry) WithSubjectAccessReviewClient(client authzclient.SubjectAccessReviewInterface) *Registry {
	r.sarclient = client
	return r
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

// AddSubjectAccessReviewFunc will add a new SubjectAccessReview function to
// the register.
// The function will be run whenever SubjectAccessReview is called with a
// requestVersion set to any recognised GroupVersionKinds for this object.  If
// obj is part of an internal API version, the review function will be called
// on all calls to registry regardless of version.  If obj cannot be recognised
// using the registry's scheme, an error will be returned.
func (r *Registry) AddSubjectAccessReviewFunc(obj runtime.Object, fn SubjectAccessReviewFunc) error {
	gvks, _, err := r.scheme.ObjectKinds(obj)
	if err != nil {
		return err
	}

	for _, gvk := range gvks {
		r.appendSubjectAccessReview(gvk, fn)
	}

	return nil
}

// Validate will run all validation functions registered for the given object.
// If the passed obj is *not* of the same version as the provided
// requestVersion, the registry will attempt to convert the object before
// calling the validation functions.
// Any validation functions registered for the objects internal API version
// will be run against the object regardless of version.
func (r *Registry) Validate(req *admissionv1.AdmissionRequest, obj runtime.Object, requestVersion schema.GroupVersionKind) field.ErrorList {
	versioned, internal := r.lookupValidateFuncs(requestVersion)
	if versioned == nil && internal == nil {
		return nil
	}

	targetObj, internalObj, err := r.convert(obj, requestVersion)
	if err != nil {
		return internalError(err)
	}

	el := field.ErrorList{}
	if versioned != nil {
		el = append(el, versioned(req, targetObj)...)
	}
	if internal != nil {
		el = append(el, internal(req, internalObj)...)
	}

	return el
}

// ValidateUpdate will run all update validation functions registered for the
// given object.
// If the passed objects are *not* of the same version as the provided
// requestVersion, the registry will attempt to convert the objects before
// calling the validation functions.
// Any validation functions registered for the objects internal API version
// will be run against the object regardless of version.
func (r *Registry) ValidateUpdate(req *admissionv1.AdmissionRequest, oldObj, obj runtime.Object, requestVersion schema.GroupVersionKind) field.ErrorList {
	versioned, internal := r.lookupValidateUpdateFuncs(requestVersion)
	if versioned == nil && internal == nil {
		return nil
	}

	targetOldObj, internalOldObj, err := r.convert(oldObj, requestVersion)
	if err != nil {
		return internalError(err)
	}

	targetObj, internalObj, err := r.convert(obj, requestVersion)
	if err != nil {
		return internalError(err)
	}

	el := field.ErrorList{}
	if versioned != nil {
		el = append(el, versioned(req, targetOldObj, targetObj)...)
	}
	if internal != nil {
		el = append(el, internal(req, internalOldObj, internalObj)...)
	}

	return el
}

// SubjectAccessReview will run all SubjectAccessReview functions registered for
// the given object.
// If the passed objects are *not* of the same version as the provided
// requestVersion, the registry will attempt to convert the objects before
// calling the review functions.
// Any review functions registered for the objects internal API version
// will be run against the object regardless of version.
func (r *Registry) SubjectAccessReview(req *admissionv1.AdmissionRequest, oldObj, obj runtime.Object, requestVersion schema.GroupVersionKind) field.ErrorList {
	versioned, internal := r.lookupSubjectAccessReviewFuncs(requestVersion)
	if versioned == nil && internal == nil {
		return nil
	}

	// No SubjectAccessReview client is present for this registry. Exit error
	// here as we cannot evaluate the request
	if r.sarclient == nil {
		return internalError(errors.New("SubjectAccessReview client not defined"))
	}

	targetOldObj, internalOldObj, err := r.convert(oldObj, requestVersion)
	if err != nil {
		return internalError(err)
	}

	targetObj, internalObj, err := r.convert(obj, requestVersion)
	if err != nil {
		return internalError(err)
	}

	el := field.ErrorList{}
	if versioned != nil {
		el = append(el, versioned(r.sarclient, req, targetOldObj, targetObj)...)
	}
	if internal != nil {
		el = append(el, internal(r.sarclient, req, internalOldObj, internalObj)...)
	}

	return el
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

func (r *Registry) lookupSubjectAccessReviewFuncs(gvk schema.GroupVersionKind) (versioned SubjectAccessReviewFunc, internal SubjectAccessReviewFunc) {
	versioned = r.subjectAccessReviewRegister[gvk]
	gvk.Version = runtime.APIVersionInternal
	internal = r.subjectAccessReviewRegister[gvk]
	return versioned, internal
}

func (r *Registry) appendValidate(gvk schema.GroupVersionKind, fn ValidateFunc) {
	existing, ok := r.validateRegister[gvk]
	if !ok {
		r.validateRegister[gvk] = fn
		return
	}

	r.validateRegister[gvk] = func(req *admissionv1.AdmissionRequest, obj runtime.Object) field.ErrorList {
		return append(existing(req, obj), fn(req, obj)...)
	}
}

func (r *Registry) appendValidateUpdate(gvk schema.GroupVersionKind, fn ValidateUpdateFunc) {
	existing, ok := r.validateUpdateRegister[gvk]
	if !ok {
		r.validateUpdateRegister[gvk] = fn
		return
	}

	r.validateUpdateRegister[gvk] = func(req *admissionv1.AdmissionRequest, oldObj, obj runtime.Object) field.ErrorList {
		return append(existing(req, oldObj, obj), fn(req, oldObj, obj)...)
	}
}

func (r *Registry) appendSubjectAccessReview(gvk schema.GroupVersionKind, fn SubjectAccessReviewFunc) {
	existing, ok := r.subjectAccessReviewRegister[gvk]
	if !ok {
		r.subjectAccessReviewRegister[gvk] = fn
		return
	}

	r.subjectAccessReviewRegister[gvk] = func(client authzclient.SubjectAccessReviewInterface, req *admissionv1.AdmissionRequest, oldObj, obj runtime.Object) field.ErrorList {
		return append(existing(client, req, oldObj, obj), fn(client, req, oldObj, obj)...)
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
