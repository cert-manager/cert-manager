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

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

// decoder knows how to decode the contents of an admission
// request into a concrete object.
type internalDecoder struct {
	scheme *runtime.Scheme
	codecs serializer.CodecFactory
}

// DecodeRaw decodes a RawExtension object.
// It errors out if rawObj is empty i.e. containing 0 raw bytes.
func (d *internalDecoder) DecodeRaw(rawObj runtime.RawExtension) (runtime.Object, error) {
	// we error out if rawObj is an empty object.
	if len(rawObj.Raw) == 0 {
		return nil, fmt.Errorf("there is no content to decode")
	}

	obj, gvk, err := d.codecs.UniversalDeserializer().Decode(rawObj.Raw, nil, nil)
	if err != nil {
		return nil, err
	}
	obj.GetObjectKind().SetGroupVersionKind(schema.GroupVersionKind{
		Group:   gvk.Group,
		Version: gvk.Version,
		Kind:    gvk.Kind,
	})

	return d.scheme.UnsafeConvertToVersion(obj, runtime.InternalGroupVersioner)
}
