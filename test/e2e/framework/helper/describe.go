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

package helper

import (
	"k8s.io/apimachinery/pkg/runtime"
	runtimejson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	kscheme "k8s.io/client-go/kubernetes/scheme"

	"github.com/cert-manager/cert-manager/e2e-tests/framework/log"
	cmscheme "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/scheme"
)

func (h *Helper) describeKubeObject(object runtime.Object) error {
	serializer := runtimejson.NewSerializerWithOptions(runtimejson.DefaultMetaFactory, kscheme.Scheme, kscheme.Scheme, runtimejson.SerializerOptions{
		Yaml:   true,
		Pretty: true,
	})
	encoder := kscheme.Codecs.WithoutConversion().EncoderForVersion(serializer, nil)
	return encoder.Encode(object, log.Writer)
}

func (h *Helper) describeCMObject(object runtime.Object) error {
	serializer := runtimejson.NewSerializerWithOptions(runtimejson.DefaultMetaFactory, cmscheme.Scheme, cmscheme.Scheme, runtimejson.SerializerOptions{
		Yaml:   true,
		Pretty: true,
	})
	encoder := cmscheme.Codecs.WithoutConversion().EncoderForVersion(serializer, nil)
	return encoder.Encode(object, log.Writer)
}
