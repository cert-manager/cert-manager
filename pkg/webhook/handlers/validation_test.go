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
	"fmt"
	"net/http"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cert-manager/cert-manager/pkg/internal/api/validation"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/install"
	v1 "github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/v1"
	v2 "github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/v2"
)

func TestRegistryBackedValidator(t *testing.T) {
	scheme := runtime.NewScheme()
	registry := validation.NewRegistry(scheme)
	install.Install(scheme)
	install.InstallValidations(registry)

	c := NewRegistryBackedValidator(logf.Log, scheme, registry)
	testTypeGVK := &metav1.GroupVersionKind{
		Group:   v1.SchemeGroupVersion.Group,
		Version: v1.SchemeGroupVersion.Version,
		Kind:    "TestType",
	}
	testTypeGVKV2 := &metav1.GroupVersionKind{
		Group:   v2.SchemeGroupVersion.Group,
		Version: v2.SchemeGroupVersion.Version,
		Kind:    "TestType",
	}
	tests := map[string]admissionTestT{
		"should not allow invalid value for 'testField' field": {
			inputRequest: admissionv1.AdmissionRequest{
				UID:         types.UID("abc"),
				RequestKind: testTypeGVK,
				Operation:   admissionv1.Create,
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
			expectedResponse: admissionv1.AdmissionResponse{
				UID:     types.UID("abc"),
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure, Code: http.StatusNotAcceptable, Reason: metav1.StatusReasonNotAcceptable,
					Message: "testField: Invalid value: \"not-allowed-value\": invalid value",
				},
			},
		},
		"should allow setting immutable field if it is not already set": {
			inputRequest: admissionv1.AdmissionRequest{
				RequestKind: testTypeGVK,
				Operation:   admissionv1.Update,
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
			expectedResponse: admissionv1.AdmissionResponse{
				Allowed: true,
			},
		},
		"should not allow setting immutable field if it is already set": {
			inputRequest: admissionv1.AdmissionRequest{
				RequestKind: testTypeGVK,
				Operation:   admissionv1.Update,
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
			expectedResponse: admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure, Code: http.StatusNotAcceptable, Reason: metav1.StatusReasonNotAcceptable,
					Message: "testFieldImmutable: Forbidden: field is immutable once set",
				},
			},
		},
		"should not allow setting immutable field if it is already set (v2)": {
			inputRequest: admissionv1.AdmissionRequest{
				RequestKind: testTypeGVKV2,
				Operation:   admissionv1.Update,
				OldObject: runtime.RawExtension{
					Raw: []byte(fmt.Sprintf(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v2",
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
	"apiVersion": "testgroup.testing.cert-manager.io/v2",
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
			expectedResponse: admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure, Code: http.StatusNotAcceptable, Reason: metav1.StatusReasonNotAcceptable,
					Message: "testFieldImmutable: Forbidden: field is immutable once set",
				},
			},
		},
		"should not allow invalid value for 'testField' field in v2": {
			inputRequest: admissionv1.AdmissionRequest{
				UID:         types.UID("abc"),
				RequestKind: testTypeGVKV2,
				Operation:   admissionv1.Create,
				Object: runtime.RawExtension{
					Raw: []byte(fmt.Sprintf(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v2",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	},
	"testField": "%s"
}
`, v2.DisallowedTestFieldValue)),
				},
			},
			expectedResponse: admissionv1.AdmissionResponse{
				UID:     types.UID("abc"),
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure, Code: http.StatusNotAcceptable, Reason: metav1.StatusReasonNotAcceptable,
					Message: "testField: Invalid value: \"not-allowed-in-v2\": value not allowed",
				},
			},
		},
		"should allow value for 'testField' field in v2 if requestKind is v1": {
			inputRequest: admissionv1.AdmissionRequest{
				UID:         types.UID("abc"),
				RequestKind: testTypeGVK,
				Operation:   admissionv1.Create,
				Object: runtime.RawExtension{
					Raw: []byte(fmt.Sprintf(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v2",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	},
	"testField": "%s"
}
`, v2.DisallowedTestFieldValue)),
				},
			},
			expectedResponse: admissionv1.AdmissionResponse{
				UID:     types.UID("abc"),
				Allowed: true,
			},
		},
		"should validate in the current APIVersion if RequestKind is not set (for Kubernetes <1.15 support)": {
			inputRequest: admissionv1.AdmissionRequest{
				UID:       types.UID("abc"),
				Kind:      *testTypeGVKV2,
				Operation: admissionv1.Create,
				Object: runtime.RawExtension{
					Raw: []byte(fmt.Sprintf(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v2",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	},
	"testField": "%s"
}
`, v2.DisallowedTestFieldValue)),
				},
			},
			expectedResponse: admissionv1.AdmissionResponse{
				UID:     types.UID("abc"),
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusFailure, Code: http.StatusNotAcceptable, Reason: metav1.StatusReasonNotAcceptable,
					Message: "testField: Invalid value: \"not-allowed-in-v2\": value not allowed",
				},
			},
		},
	}

	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			runAdmissionTest(t, c.Validate, test)
		})
	}
}
