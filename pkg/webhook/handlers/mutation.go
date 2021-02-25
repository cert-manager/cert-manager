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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/go-logr/logr"
	"github.com/mattbaird/jsonpatch"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	apijson "k8s.io/apimachinery/pkg/runtime/serializer/json"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

type SchemeBackedDefaulter struct {
	log    logr.Logger
	scheme *runtime.Scheme
	codec  runtime.Codec
}

func NewSchemeBackedDefaulter(log logr.Logger, scheme *runtime.Scheme) *SchemeBackedDefaulter {
	factory := serializer.NewCodecFactory(scheme)
	serializer := apijson.NewSerializerWithOptions(apijson.DefaultMetaFactory, scheme, scheme, apijson.SerializerOptions{})
	encoder := factory.WithoutConversion().EncoderForVersion(serializer, nil)
	decoder := factory.UniversalDeserializer()
	return &SchemeBackedDefaulter{
		log:    log,
		scheme: scheme,
		codec:  runtime.NewCodec(encoder, decoder),
	}
}

func (c *SchemeBackedDefaulter) Mutate(admissionSpec *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	status := &admissionv1.AdmissionResponse{}
	status.UID = admissionSpec.UID

	// decode the raw object data
	obj, _, err := c.codec.Decode(admissionSpec.Object.Raw, nil, nil)
	if err != nil {
		status.Result = &metav1.Status{
			Status: metav1.StatusFailure, Code: http.StatusInternalServerError, Reason: metav1.StatusReasonInternalError,
			Message: fmt.Sprintf("Failed to decode object: %v", err.Error()),
		}
		return status
	}

	// create a copy of the resource
	defaultedObj := obj.DeepCopyObject()
	// apply defaults to the object
	c.scheme.Default(defaultedObj)
	// encode the default object to JSON
	buf := bytes.Buffer{}
	if err := c.codec.Encode(defaultedObj, &buf); err != nil {
		status.Result = &metav1.Status{
			Status: metav1.StatusFailure, Code: http.StatusInternalServerError, Reason: metav1.StatusReasonInternalError,
			Message: fmt.Sprintf("Failed to encode defaulted data: %v", err.Error()),
		}
		return status
	}
	// create a merge patch between the old and the new json data
	ops, err := jsonpatch.CreatePatch(admissionSpec.Object.Raw, buf.Bytes())
	if err != nil {
		status.Result = &metav1.Status{
			Status: metav1.StatusFailure, Code: http.StatusInternalServerError, Reason: metav1.StatusReasonInternalError,
			Message: fmt.Sprintf("Failed to generate json patch: %v", err.Error()),
		}
		return status
	}
	// sort options by path to ensure the output of CreatePatch is deterministic
	sortOps(ops)

	patch, err := json.Marshal(ops)
	if err != nil {
		status.Result = &metav1.Status{
			Status: metav1.StatusFailure, Code: http.StatusInternalServerError, Reason: metav1.StatusReasonInternalError,
			Message: fmt.Sprintf("Failed to generate json patch: %v", err.Error()),
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

func sortOps(ops []jsonpatch.JsonPatchOperation) {
	sort.Slice(ops, func(i, j int) bool {
		return ops[i].Path < ops[j].Path
	})
}
