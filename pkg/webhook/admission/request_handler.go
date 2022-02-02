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

package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	apijson "k8s.io/apimachinery/pkg/runtime/serializer/json"

	"github.com/cert-manager/cert-manager/pkg/webhook/handlers"
)

// RequestHandler is an implementation of the webhook's request handling that
// invokes a validating and/or mutating admission plugin (or chain of plugins).
//
// All runtime.Objects passed to the mutation and validation handlers will be in
// their internal versions to make handling multiple API versions easier.
//
// During mutation, objects will be decoded using the scheme provided during the
// NewRequestHandler call. This scheme will also be used to invoke defaulting functions
// when the object is decoded.
// This means that all resources passed to mutating admission plugins will have default
// values applied before converting them into the internal version.
type RequestHandler struct {
	scheme *runtime.Scheme

	// codecFactory used to create encoders and decoders
	codecFactory serializer.CodecFactory

	// serializer used to write resources as JSON after mutation to determine
	// the final jsonpatch for resources
	serializer *apijson.Serializer

	// decoder used to decode & convert resources in AdmissionRequests into
	// their internal versions
	decoder runtime.Decoder

	validator ValidationInterface
	mutator   MutationInterface
}

// NewRequestHandler will construct a new request handler using the given scheme for
// conversion & defaulting. Either validator or mutator can be nil, and if so no
// action will be taken.
func NewRequestHandler(scheme *runtime.Scheme, validator ValidationInterface, mutator MutationInterface) *RequestHandler {
	cf := serializer.NewCodecFactory(scheme)
	return &RequestHandler{
		scheme:       scheme,
		codecFactory: cf,
		serializer:   apijson.NewSerializerWithOptions(apijson.DefaultMetaFactory, scheme, scheme, apijson.SerializerOptions{}),
		decoder:      cf.UniversalDecoder(),
		validator:    validator,
		mutator:      mutator,
	}
}

var _ handlers.ValidatingAdmissionHook = &RequestHandler{}
var _ handlers.MutatingAdmissionHook = &RequestHandler{}

// Validate will decode the Object (and OldObject, if set) in the AdmissionRequest into the
// internal API version.
// It will then invoke the validation handler to build a list of warning messages and any
// errors generated during the admission chain.
func (rh *RequestHandler) Validate(ctx context.Context, admissionSpec *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	status := &admissionv1.AdmissionResponse{}
	status.UID = admissionSpec.UID
	// short-path if there is no validator actually registered or the handler does not handle this operation.
	if rh.validator == nil || !rh.validator.Handles(admissionSpec.Operation) {
		status.Allowed = true
		return status
	}

	// decode new version of object
	obj, err := rh.deseralizeToInternalVersion(admissionSpec.Object.Raw)
	if err != nil {
		return badRequestError(status, err)
	}

	// attempt to decode old object
	var oldObj runtime.Object
	if len(admissionSpec.OldObject.Raw) > 0 {
		oldObj, err = rh.deseralizeToInternalVersion(admissionSpec.OldObject.Raw)
		if err != nil {
			return badRequestError(status, err)
		}
	}

	warnings, err := rh.validator.Validate(ctx, *admissionSpec, oldObj, obj)
	status.Warnings = warnings

	// return with allowed = false if any errors occurred
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

func (rh *RequestHandler) Mutate(ctx context.Context, admissionSpec *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	status := &admissionv1.AdmissionResponse{}
	status.UID = admissionSpec.UID
	status.Allowed = true
	// short-path if there is no mutator actually registered
	// we still continue if the mutator does not handle the resource so scheme-registered
	// defaulting functions are still run against the object.
	if rh.mutator == nil {
		status.Allowed = true
		return status
	}

	// If the resource submitted to the webhook is in a different version to the request version,
	// we must take special steps to ensure the correct defaults are applied to the resource (as
	// defaults are applied by the decoder when the resource is decoded in the version of the
	// encoded resource).
	obj, errResponse := rh.decodeRequestObject(status, admissionSpec.Kind, *admissionSpec.RequestKind, admissionSpec.Object.Raw)
	if errResponse != nil {
		return errResponse
	}

	if rh.mutator.Handles(admissionSpec.Operation) {
		if err := rh.mutator.Mutate(ctx, *admissionSpec, obj); err != nil {
			return internalServerError(status, err)
		}
	}

	// Convert the object into the original version that was submitted to the webhook
	// before generating the patch.
	outputGroupVersioner := runtime.NewMultiGroupVersioner(schema.GroupVersion{Group: admissionSpec.Kind.Group, Version: admissionSpec.Kind.Version})
	finalObject, err := rh.scheme.ConvertToVersion(obj, outputGroupVersioner)
	if err != nil {
		return internalServerError(status, err)
	}

	patch, err := rh.createMutatePatch(admissionSpec, finalObject)
	if err != nil {
		return internalServerError(status, err)
	}

	patchType := admissionv1.PatchTypeJSONPatch
	status.PatchType = &patchType
	status.Patch = patch

	return status
}

// decodeRequestObject will decode the given 'bytes' into the internal API version.
// It will apply defaults using the 'defaultsInGVK', regardless of what API version
// the encoded bytes are in.
func (rh *RequestHandler) decodeRequestObject(status *admissionv1.AdmissionResponse, objectGVK, defaultInGVK metav1.GroupVersionKind, bytes []byte) (runtime.Object, *admissionv1.AdmissionResponse) {
	if objectGVK == defaultInGVK {
		obj, _, err := rh.decoder.Decode(bytes, nil, nil)
		if err != nil {
			return nil, badRequestError(status, err)
		}
		return obj, nil
	}

	// Decode the object to the internal version without defaulting
	internalObj, err := rh.deseralizeToInternalVersion(bytes)
	if err != nil {
		return nil, badRequestError(status, err)
	}

	// Now convert into the request version so we can apply the appropriate defaults
	requestGroupVersioner := runtime.NewMultiGroupVersioner(schema.GroupVersion{Group: defaultInGVK.Group, Version: defaultInGVK.Version})
	requestObj, err := rh.scheme.ConvertToVersion(internalObj, requestGroupVersioner)
	if err != nil {
		return nil, internalServerError(status, err)
	}

	// At last, apply defaults in the request API version
	rh.scheme.Default(requestObj)

	// Finally, convert the resource back to the internal version so regular admission can proceed
	obj, err := rh.scheme.ConvertToVersion(requestObj, runtime.InternalGroupVersioner)
	if err != nil {
		return nil, internalServerError(status, err)
	}

	return obj, nil
}

// deseralizeToInternalVersion will decode an object into its internal version
// without applying default values.
func (rh *RequestHandler) deseralizeToInternalVersion(bytes []byte) (runtime.Object, error) {
	// First, use the UniversalDeserializer to decode the bytes (which does not perform
	// conversion or defaulting).
	obj, _, err := rh.codecFactory.UniversalDeserializer().Decode(bytes, nil, nil)
	if err != nil {
		return nil, err
	}

	// Then convert to the internal version
	return rh.scheme.ConvertToVersion(obj, runtime.InternalGroupVersioner)
}

func badRequestError(status *admissionv1.AdmissionResponse, err error) *admissionv1.AdmissionResponse {
	status.Allowed = false
	status.Result = &metav1.Status{
		Status: metav1.StatusFailure, Code: http.StatusBadRequest, Reason: metav1.StatusReasonBadRequest,
		Message: err.Error(),
	}
	return status
}

func internalServerError(status *admissionv1.AdmissionResponse, err error) *admissionv1.AdmissionResponse {
	status.Allowed = false
	status.Result = &metav1.Status{
		Status: metav1.StatusFailure, Code: http.StatusInternalServerError, Reason: metav1.StatusReasonInternalError,
		Message: err.Error(),
	}
	return status
}

// createMutatePatch will generate a JSON patch based upon the given original
// raw object, and the mutated typed object.
func (rh *RequestHandler) createMutatePatch(req *admissionv1.AdmissionRequest, obj runtime.Object) ([]byte, error) {
	var buf bytes.Buffer

	encoder := rh.codecFactory.EncoderForVersion(rh.serializer, schema.GroupVersion{Group: req.Kind.Group, Version: req.Kind.Version})
	if err := encoder.Encode(obj, &buf); err != nil {
		return nil, fmt.Errorf("failed to encode object after mutation: %s", err)
	}

	ops, err := jsonpatch.CreatePatch(req.Object.Raw, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to set mutation patch: %s", err)
	}

	sortOps(ops)

	patch, err := json.Marshal(ops)
	if err != nil {
		return nil, fmt.Errorf("failed to generate json patch: %s", err)
	}

	return patch, nil
}

func sortOps(ops []jsonpatch.JsonPatchOperation) {
	sort.Slice(ops, func(i, j int) bool {
		return ops[i].Path < ops[j].Path
	})
}
