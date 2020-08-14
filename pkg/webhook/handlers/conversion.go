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
	"bytes"
	"fmt"
	"net/http"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apijson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/runtime/serializer/versioning"

	logf "github.com/jetstack/cert-manager/pkg/logs"
)

type SchemeBackedConverter struct {
	log        logr.Logger
	scheme     *runtime.Scheme
	serializer *apijson.Serializer
}

func NewSchemeBackedConverter(log logr.Logger, scheme *runtime.Scheme) *SchemeBackedConverter {
	serializer := apijson.NewSerializerWithOptions(apijson.DefaultMetaFactory, scheme, scheme, apijson.SerializerOptions{})
	return &SchemeBackedConverter{
		log:        log,
		scheme:     scheme,
		serializer: serializer,
	}
}

func (c *SchemeBackedConverter) Convert(conversionSpec *apiextensionsv1.ConversionRequest) *apiextensionsv1.ConversionResponse {
	status := &apiextensionsv1.ConversionResponse{}
	status.UID = conversionSpec.UID
	status.ConvertedObjects = make([]runtime.RawExtension, 0)

	desiredGV, err := schema.ParseGroupVersion(conversionSpec.DesiredAPIVersion)
	if err != nil {
		status.Result = metav1.Status{
			Status: metav1.StatusFailure, Code: http.StatusBadRequest, Reason: metav1.StatusReasonBadRequest,
			Message: fmt.Sprintf("Failed to parse desired apiVersion: %v", err.Error()),
		}
		return status
	}

	groupVersioner := schema.GroupVersions([]schema.GroupVersion{desiredGV})
	codec := versioning.NewCodec(c.serializer, c.serializer, runtime.UnsafeObjectConvertor(c.scheme), c.scheme, c.scheme, nil, groupVersioner, runtime.InternalGroupVersioner, c.scheme.Name())

	c.log.V(logf.DebugLevel).Info("Parsed desired groupVersion", "desired_group_version", desiredGV)
	for _, raw := range conversionSpec.Objects {
		decodedObject, currentGVK, err := codec.Decode(raw.Raw, nil, nil)
		if err != nil {
			status.Result = metav1.Status{
				Status: metav1.StatusFailure, Code: http.StatusBadRequest, Reason: metav1.StatusReasonBadRequest,
				Message: fmt.Sprintf("Failed to decode into apiVersion: %v", err.Error()),
			}
			return status
		}
		c.log.V(logf.DebugLevel).Info("Decoded resource", "decoded_group_version_kind", currentGVK)

		buf := bytes.Buffer{}
		if err := codec.Encode(decodedObject, &buf); err != nil {
			status.Result = metav1.Status{
				Status: metav1.StatusFailure, Code: http.StatusBadRequest, Reason: metav1.StatusReasonBadRequest,
				Message: fmt.Sprintf("Failed to convert to desired apiVersion: %v", err.Error()),
			}
			return status
		}

		status.ConvertedObjects = append(status.ConvertedObjects, runtime.RawExtension{Raw: buf.Bytes()})
	}

	status.Result.Status = metav1.StatusSuccess
	return status
}
