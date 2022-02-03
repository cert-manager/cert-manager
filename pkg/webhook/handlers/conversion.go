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
	"fmt"
	"net/http"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apijson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/runtime/serializer/versioning"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

type SchemeBackedConverter struct {
	log        logr.Logger
	scheme     *runtime.Scheme
	serializer *apijson.Serializer
}

var _ ConversionHook = &SchemeBackedConverter{}

func NewSchemeBackedConverter(log logr.Logger, scheme *runtime.Scheme) *SchemeBackedConverter {
	serializer := apijson.NewSerializerWithOptions(apijson.DefaultMetaFactory, scheme, scheme, apijson.SerializerOptions{})
	return &SchemeBackedConverter{
		log:        log,
		scheme:     scheme,
		serializer: serializer,
	}
}

func (c *SchemeBackedConverter) convertObjects(desiredAPIVersion string, objects []runtime.RawExtension) ([]runtime.RawExtension, error) {
	desiredGV, err := schema.ParseGroupVersion(desiredAPIVersion)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse desired apiVersion: %v", err)
	}

	c.log.V(logf.DebugLevel).Info("Parsed desired groupVersion", "desired_group_version", desiredGV)

	groupVersioner := schema.GroupVersions([]schema.GroupVersion{desiredGV})
	codec := versioning.NewCodec(
		c.serializer,
		c.serializer,
		runtime.UnsafeObjectConvertor(c.scheme),
		c.scheme,
		c.scheme,
		nil,
		groupVersioner,
		runtime.InternalGroupVersioner, c.scheme.Name(),
	)

	convertedObjects := make([]runtime.RawExtension, len(objects))
	for i, raw := range objects {
		decodedObject, currentGVK, err := codec.Decode(raw.Raw, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode into apiVersion: %v", err)
		}
		c.log.V(logf.DebugLevel).Info("Decoded resource", "decoded_group_version_kind", currentGVK)
		buf := bytes.Buffer{}
		if err := codec.Encode(decodedObject, &buf); err != nil {
			return nil, fmt.Errorf("Failed to convert to desired apiVersion: %v", err)
		}
		convertedObjects[i] = runtime.RawExtension{Raw: buf.Bytes()}
	}
	return convertedObjects, nil
}

func (c *SchemeBackedConverter) Convert(conversionSpec *apiextensionsv1.ConversionRequest) *apiextensionsv1.ConversionResponse {
	result := metav1.Status{Status: metav1.StatusSuccess}
	convertedObjects, err := c.convertObjects(conversionSpec.DesiredAPIVersion, conversionSpec.Objects)
	if err != nil {
		result.Status = metav1.StatusFailure
		result.Code = http.StatusBadRequest
		result.Reason = metav1.StatusReasonBadRequest
		result.Message = err.Error()
	}
	return &apiextensionsv1.ConversionResponse{
		UID:              conversionSpec.UID,
		ConvertedObjects: convertedObjects,
		Result:           result,
	}
}
