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
	"flag"
	"reflect"
	"testing"

	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog"
	"k8s.io/klog/klogr"
	"k8s.io/utils/diff"

	"github.com/jetstack/cert-manager/pkg/internal/apis/certmanager/install"
)

func TestDefaultCertificate(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)

	log := klogr.New()
	klog.InitFlags(flag.CommandLine)
	c := NewSchemeBackedDefaulter(log, scheme, "certificates", "certificate")
	tests := map[string]testT{
		"convert Certificate from v1alpha1 to v1beta1": {
			inputRequest: admissionv1beta1.AdmissionRequest{
				Object: runtime.RawExtension{
					Raw: []byte(`{"apiVersion": "certmanager.k8s.io/v1alpha1",
"kind": "Certificate",
"metadata": {
  "name": "testing",
  "namespace": "abc",
  "creationTimestamp": null
},
"spec": {
  "secretName": "secret-name",
  "organization": [
    "abc"
  ],
  "dnsNames": [
    "example.com"
  ]
}, "status": {}}
`),
				},
			},
			expectedResponse: admissionv1beta1.AdmissionResponse{
				Patch: []byte{},
			},
		},
	}

	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			runTest(t, c.Mutate, test)
		})
	}
}

type testT struct {
	inputRequest     admissionv1beta1.AdmissionRequest
	expectedResponse admissionv1beta1.AdmissionResponse
}

type convertFn func(request *admissionv1beta1.AdmissionRequest) *admissionv1beta1.AdmissionResponse

func runTest(t *testing.T, fn convertFn, test testT) {
	resp := fn(&test.inputRequest)
	if !reflect.DeepEqual(&test.expectedResponse, resp) {
		t.Errorf("Response was not as expected: %v", diff.ObjectGoPrintSideBySide(&test.expectedResponse, resp))
	}
}
