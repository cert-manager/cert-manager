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

package admission

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/utils/ptr"
)

// decoder knows how to decode the contents of an admission
// request into a concrete object.
type internalDecoder struct {
	scheme *runtime.Scheme
	codecs serializer.CodecFactory
}

// DecodeRaw decodes a RawExtension object.
// It errors out if rawObj is empty i.e. containing 0 raw bytes.
func (d *internalDecoder) DecodeRaw(rawObj runtime.RawExtension, rawKind schema.GroupVersionKind) (runtime.Object, error) {
	// we error out if rawObj is an empty object.
	if len(rawObj.Raw) == 0 {
		return nil, fmt.Errorf("there is no content to decode")
	}

	obj, gvk, err := d.codecs.UniversalDeserializer().Decode(rawObj.Raw, ptr.To(rawKind), nil)
	if err != nil {
		return nil, err
	}
	if obj.GetObjectKind().GroupVersionKind().Empty() && gvk != nil {
		obj.GetObjectKind().SetGroupVersionKind(*gvk)
	}

	return d.scheme.UnsafeConvertToVersion(obj, runtime.InternalGroupVersioner)
}

// DecodeRawUnstructured decodes a RawExtension object into an unstructured object.
func DecodeRawUnstructured(rawObj runtime.RawExtension, rawKind schema.GroupVersionKind) (*unstructured.Unstructured, error) {
	if len(rawObj.Raw) == 0 {
		return nil, fmt.Errorf("there is no content to decode")
	}

	obj := &unstructured.Unstructured{}
	if err := obj.UnmarshalJSON(rawObj.Raw); err != nil {
		return nil, err
	}
	if obj.GetObjectKind().GroupVersionKind().Empty() {
		obj.GetObjectKind().SetGroupVersionKind(rawKind)
	}

	return obj, nil
}
