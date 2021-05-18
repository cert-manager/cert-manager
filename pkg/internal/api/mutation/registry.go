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

// Package mutation allows a caller to automatically register, lookup and call
// API mutation functions.
// It is similar to runtime.Scheme and is designed to make writing and
// consuming API mutation functions easier.
// This registry also handles adding scheme defaults, even if no mutation
// functions are defined for that type. Any type where defaulting is desired
// should be registered.
// Functions are designed to update the incoming object, or new object, which
// will then have a patch generated and returned to the master Mutation.
package mutation

import (
	"bytes"
	"encoding/json"
	"fmt"

	"gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	apijson "k8s.io/apimachinery/pkg/runtime/serializer/json"
)

// Registry is used to store and lookup references to mutation functions for
// given Kubernetes API types. API types will be converted into internal API
// versions during mutation, then converted back to the target version when
// generating the patch.
type Registry struct {
	codec  runtime.Codec
	scheme *runtime.Scheme

	mutateRegister       map[schema.GroupVersionKind]MutateFunc
	mutateUpdateRegister map[schema.GroupVersionKind]MutateUpdateFunc
}

type MutateFunc func(req *admissionv1.AdmissionRequest, obj runtime.Object)
type MutateUpdateFunc func(req *admissionv1.AdmissionRequest, old, new runtime.Object)

// NewRegistry creates a new empty registry, backed by the provided Scheme.
func NewRegistry(scheme *runtime.Scheme) *Registry {
	factory := serializer.NewCodecFactory(scheme)
	serializer := apijson.NewSerializerWithOptions(apijson.DefaultMetaFactory, scheme, scheme, apijson.SerializerOptions{})
	encoder := factory.WithoutConversion().EncoderForVersion(serializer, nil)
	decoder := factory.UniversalDeserializer()
	return &Registry{
		codec:                runtime.NewCodec(encoder, decoder),
		scheme:               scheme,
		mutateRegister:       make(map[schema.GroupVersionKind]MutateFunc),
		mutateUpdateRegister: make(map[schema.GroupVersionKind]MutateUpdateFunc),
	}
}

// AddMutateFunc will add a new mutation function to the register. The function
// will be run whenever a Mutate is called with a CREATE operation, and API
// type whose internal version is registered. Registered types MUST be that of the
// internal version of the target resource kind.
func (r *Registry) AddMutateFunc(obj runtime.Object, fn MutateFunc) error {
	gvks, _, err := r.scheme.ObjectKinds(obj)
	if err != nil {
		return err
	}

	for _, gvk := range gvks {
		r.appendMutate(gvk, fn)
	}

	return nil
}

// AddMutateFunc will add a new mutation function to the register. The function
// will be run whenever a Mutate is called with an UPDATE operation, and API
// type whose internal version is registered. Registered types MUST be that of the
// internal version of the target resource kind.
func (r *Registry) AddMutateUpdateFunc(obj runtime.Object, fn MutateUpdateFunc) error {
	gvks, _, err := r.scheme.ObjectKinds(obj)
	if err != nil {
		return err
	}

	for _, gvk := range gvks {
		r.appendMutateUpdate(gvk, fn)
	}

	return nil
}

// Mutate will run all mutation functions registed on CREATE and UPDATE
// operations over the internal type of the given resource.
// The object is converted to its internal version before either a CREATE or
// UPDATE mutation is applied to the object. The object is then converted to
// the requested version, and defaults applied for that schema.
// A JSON patch is then generated for the target resource version.
// Defaulting is always applied against the given resource, regardless of
// whether any mutation functions are defined.
func (r *Registry) Mutate(req *admissionv1.AdmissionRequest) ([]byte, error) {
	// Create GroupVersionKind where the Version is set to internal.
	gvk := schema.GroupVersionKind{
		Group: req.RequestKind.Group,
		// Set version to internal API version
		Version: runtime.APIVersionInternal,
		Kind:    req.RequestKind.Kind,
	}

	// Convert the incoming resource to the internal type
	internal, err := r.convert(req.Object.Raw, gvk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert object: %s", err)
	}

	switch req.Operation {
	case admissionv1.Create:
		// Attempt to retrieve the registered CREATE mutating functions, and apply
		// to the internal type.
		mutate := r.mutateRegister[gvk]
		if mutate == nil {
			break
		}

		mutate(req, internal)

	case admissionv1.Update:
		// Attempt to retrieve the registered UPDATE mutating functions, and apply
		// to the internal type.

		// decode the old raw object data
		oldInternal, err := r.convert(req.OldObject.Raw, gvk)
		if err != nil {
			return nil, fmt.Errorf("failed to decode old admission object: %s", err)
		}

		mutate := r.mutateUpdateRegister[gvk]
		if mutate == nil {
			break
		}

		// Pass both the old and new internal types to mutate
		mutate(req, oldInternal, internal)

	default:
		// If not under a CREATE or UPDATE operation, exit early
		return nil, nil
	}

	// Convert the mutated internal object into the target resource version.
	target, err := r.scheme.New(schema.GroupVersionKind{
		Group:   req.RequestKind.Group,
		Version: req.RequestKind.Version,
		Kind:    req.RequestKind.Kind,
	})
	if err != nil {
		return nil, err
	}
	if err := r.scheme.Convert(internal, target, nil); err != nil {
		return nil, err
	}

	// Apply defaults to the target resource.
	r.scheme.Default(target)

	// Generate a JSON patch based on the incoming resource and the mutated object.
	return r.createMutatePatch(req, target)
}

// convert converts a raw resource byte slice to an internal versioned resource, based on the given GroupKind.
func (r *Registry) convert(rawObj []byte, gvk schema.GroupVersionKind) (runtime.Object, error) {
	gvk.Version = runtime.APIVersionInternal
	obj, _, err := r.codec.Decode(rawObj, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decode admission object: %s", err)
	}

	targetObj, err := r.scheme.New(gvk)
	if err != nil {
		return nil, err
	}

	if err := r.scheme.Convert(obj, targetObj, nil); err != nil {
		return nil, err
	}

	return targetObj, nil
}

// createMutatePatch will generate a JSON patch based upon the given original
// raw object, and the mutated typed object.
func (r *Registry) createMutatePatch(req *admissionv1.AdmissionRequest, obj runtime.Object) ([]byte, error) {
	var buf bytes.Buffer
	if err := r.codec.Encode(obj, &buf); err != nil {
		return nil, fmt.Errorf("failed to encode object after mutation: %s", err)
	}

	ops, err := jsonpatch.CreatePatch(req.Object.Raw, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to set mutation patch: %s", err)
	}

	patch, err := json.Marshal(ops)
	if err != nil {
		return nil, fmt.Errorf("failed to generate json patch: %s", err)
	}

	return patch, nil
}

func (r *Registry) appendMutate(gvk schema.GroupVersionKind, fn MutateFunc) {
	existing, ok := r.mutateRegister[gvk]
	if !ok {
		r.mutateRegister[gvk] = fn
		return
	}

	r.mutateRegister[gvk] = func(aspec *admissionv1.AdmissionRequest, obj runtime.Object) {
		existing(aspec, obj)
		fn(aspec, obj)
	}
}

func (r *Registry) appendMutateUpdate(gvk schema.GroupVersionKind, fn MutateUpdateFunc) {
	existing, ok := r.mutateUpdateRegister[gvk]
	if !ok {
		r.mutateUpdateRegister[gvk] = fn
		return
	}

	r.mutateUpdateRegister[gvk] = func(aspec *admissionv1.AdmissionRequest, oldObj, newObj runtime.Object) {
		existing(aspec, oldObj, newObj)
		fn(aspec, oldObj, newObj)
	}
}
