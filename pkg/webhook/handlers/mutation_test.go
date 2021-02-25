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
	"encoding/json"
	"reflect"
	"testing"

	"github.com/mattbaird/jsonpatch"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2/klogr"
	"k8s.io/utils/diff"

	"github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/install"
)

var (
	jsonPatchType = admissionv1.PatchTypeJSONPatch
)

func responseForOperations(ops ...jsonpatch.JsonPatchOperation) []byte {
	b, err := json.Marshal(ops)
	if err != nil {
		// this shouldn't ever be reached
		panic("failed to encode JSON test data")
	}
	return b
}

func TestDefaultCertificate(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)

	log := klogr.New()
	c := NewSchemeBackedDefaulter(log, scheme)
	tests := map[string]admissionTestT{
		"apply defaults to TestType": {
			inputRequest: admissionv1.AdmissionRequest{
				UID: types.UID("abc"),
				Object: runtime.RawExtension{
					Raw: []byte(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v1",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	}
}
`),
				},
			},
			expectedResponse: admissionv1.AdmissionResponse{
				UID:     types.UID("abc"),
				Allowed: true,
				Patch: responseForOperations(
					jsonpatch.JsonPatchOperation{
						Operation: "add",
						Path:      "/testField",
						Value:     "",
					},
					jsonpatch.JsonPatchOperation{
						Operation: "add",
						Path:      "/testFieldImmutable",
						Value:     "",
					},
					jsonpatch.JsonPatchOperation{
						Operation: "add",
						Path:      "/testFieldPtr",
						Value:     `teststr`,
					},
				),
				PatchType: &jsonPatchType,
			},
		},
	}

	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			runAdmissionTest(t, c.Mutate, test)
		})
	}
}

type admissionTestT struct {
	inputRequest     admissionv1.AdmissionRequest
	expectedResponse admissionv1.AdmissionResponse
}

type admissionFn func(request *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse

func runAdmissionTest(t *testing.T, fn admissionFn, test admissionTestT) {
	resp := fn(&test.inputRequest)
	if !reflect.DeepEqual(&test.expectedResponse, resp) {
		t.Errorf("Response was not as expected: %v", diff.ObjectGoPrintSideBySide(&test.expectedResponse, resp))
	}
}
