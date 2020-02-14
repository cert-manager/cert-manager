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

package install

import (
	"bytes"
	"io/ioutil"
	"testing"

	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsinstall "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	jsonserializer "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/runtime/serializer/versioning"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	crdfuzz "github.com/munnerz/crd-schema-fuzz"

	"github.com/jetstack/cert-manager/pkg/api"
	acmefuzzer "github.com/jetstack/cert-manager/pkg/internal/apis/acme/fuzzer"
)

func TestPruneTypes(t *testing.T) {
	crdfuzz.SchemaFuzzTestForInternalCRD(t, api.Scheme, getCRD(t, "orders.acme.cert-manager.io"), acmefuzzer.Funcs)
	crdfuzz.SchemaFuzzTestForInternalCRD(t, api.Scheme, getCRD(t, "challenges.acme.cert-manager.io"), acmefuzzer.Funcs)
}

func getCRD(t *testing.T, resourceName string) *apiextensions.CustomResourceDefinition {
	internalScheme := runtime.NewScheme()
	utilruntime.Must(metav1.AddMetaToScheme(internalScheme))
	apiextensionsinstall.Install(internalScheme)
	serializer := jsonserializer.NewSerializerWithOptions(jsonserializer.DefaultMetaFactory, internalScheme, internalScheme, jsonserializer.SerializerOptions{
		Yaml: true,
	})
	convertor := runtime.UnsafeObjectConvertor(internalScheme)
	codec := versioning.NewCodec(serializer, serializer, convertor, internalScheme, internalScheme, internalScheme, runtime.InternalGroupVersioner, runtime.InternalGroupVersioner, internalScheme.Name())

	data, err := ioutil.ReadFile("../../../../../deploy/manifests/00-crds.yaml")
	if err != nil {
		t.Fatalf("Failed to read CRD input file: %v", err)
		return nil
	}

	individualCRDs := bytes.Split(data, []byte("---"))
	for _, crdData := range individualCRDs {
		crd := &apiextensions.CustomResourceDefinition{}
		_, _, err := codec.Decode(crdData, nil, crd)
		if err != nil {
			t.Fatalf("Failed to decode CRD data: %v", err)
			return nil
		}

		if crd.ObjectMeta.Name == resourceName {
			return crd
		}
	}

	t.Fatalf("Failed to find CRD: %v", resourceName)
	return nil
}
