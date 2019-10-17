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
	"fmt"
	"net/http"
	"testing"

	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/klog/klogr"

	"github.com/jetstack/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup"
	"github.com/jetstack/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/install"
	"github.com/jetstack/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/v1"
	"github.com/jetstack/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/validation"
)

func TestFuncBackedValidator(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)

	log := klogr.New()
	c := NewFuncBackedValidator(log, scheme, map[schema.GroupKind]Validator{
		{Group: testgroup.GroupName, Kind: "TestType"}: ValidatorFunc(&v1.TestType{}, validation.ValidateTestType, validation.ValidateTestTypeUpdate),
	})
	testTypeGVK := metav1.GroupVersionKind{
		Group:   v1.SchemeGroupVersion.Group,
		Version: v1.SchemeGroupVersion.Version,
		Kind:    "TestType",
	}
	tests := map[string]testT{
		"should not allow invalid value for 'testField' field": {
			inputRequest: admissionv1beta1.AdmissionRequest{
				Kind: testTypeGVK,
				Object: runtime.RawExtension{
					Raw: []byte(fmt.Sprintf(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v1",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	},
	"testField": "%s"
}
`, v1.TestFieldValueNotAllowed)),
				},
			},
			expectedResponse: admissionv1beta1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure, Code: http.StatusNotAcceptable, Reason: metav1.StatusReasonNotAcceptable,
					Message: "testField: Invalid value: \"not-allowed-value\": invalid value",
				},
			},
		},
		"should allow setting immutable field if it is not already set": {
			inputRequest: admissionv1beta1.AdmissionRequest{
				Kind: testTypeGVK,
				OldObject: runtime.RawExtension{
					Raw: []byte(fmt.Sprintf(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v1",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	}
}
`)),
				},
				Object: runtime.RawExtension{
					Raw: []byte(fmt.Sprintf(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v1",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	},
	"testFieldImmutable": "abc"
}
`)),
				},
			},
			expectedResponse: admissionv1beta1.AdmissionResponse{
				Allowed: true,
			},
		},
		"should not allow setting immutable field if it is already set": {
			inputRequest: admissionv1beta1.AdmissionRequest{
				Kind: testTypeGVK,
				OldObject: runtime.RawExtension{
					Raw: []byte(fmt.Sprintf(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v1",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	},
	"testFieldImmutable": "oldvalue"
}
`)),
				},
				Object: runtime.RawExtension{
					Raw: []byte(fmt.Sprintf(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v1",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	},
	"testFieldImmutable": "abc"
}
`)),
				},
			},
			expectedResponse: admissionv1beta1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure, Code: http.StatusNotAcceptable, Reason: metav1.StatusReasonNotAcceptable,
					Message: "testFieldImmutable: Forbidden: field is immutable once set",
				},
			},
		},
	}

	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			runTest(t, c.Validate, test)
		})
	}
}
