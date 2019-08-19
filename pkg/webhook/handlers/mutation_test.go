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
	"encoding/json"
	"flag"
	"reflect"
	"testing"

	"github.com/mattbaird/jsonpatch"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog"
	"k8s.io/klog/klogr"
	"k8s.io/utils/diff"

	"github.com/jetstack/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup"
	"github.com/jetstack/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/install"
)

var (
	jsonPatchType = admissionv1beta1.PatchTypeJSONPatch
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
	klog.InitFlags(flag.CommandLine)
	c := NewSchemeBackedDefaulter(log, testgroup.GroupName, scheme)
	tests := map[string]testT{
		"convert Certificate from v1alpha1 to v1beta1": {
			inputRequest: admissionv1beta1.AdmissionRequest{
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
			expectedResponse: admissionv1beta1.AdmissionResponse{
				Allowed: true,
				Patch: responseForOperations(
					jsonpatch.JsonPatchOperation{
						Operation: "add",
						Path:      "/testField",
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
			runTest(t, c.Admit, test)
		})
	}
}

type testT struct {
	inputRequest     admissionv1beta1.AdmissionRequest
	expectedResponse admissionv1beta1.AdmissionResponse
}

type mutateFn func(request *admissionv1beta1.AdmissionRequest) *admissionv1beta1.AdmissionResponse

func runTest(t *testing.T, fn mutateFn, test testT) {
	resp := fn(&test.inputRequest)
	if !reflect.DeepEqual(&test.expectedResponse, resp) {
		t.Errorf("Response was not as expected: %v", diff.ObjectGoPrintSideBySide(&test.expectedResponse, resp))
	}
}
