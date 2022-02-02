/*
Copyright 2021 The cert-manager Authors.

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

package admission_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/diff"

	"github.com/cert-manager/cert-manager/pkg/webhook/admission"
	"github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup"
	"github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/install"
)

var (
	jsonPatchType = admissionv1.PatchTypeJSONPatch
)

// Tests to ensure that the RequestHandler applies scheme-registered
// defaults when mutating objects.
func TestRequestHandler_MutateAppliesDefaultValues(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)

	rh := admission.NewRequestHandler(scheme, nil, testMutator{
		handles: true,
		mutate: func(_ context.Context, _ admissionv1.AdmissionRequest, obj runtime.Object) error {
			obj.(*testgroup.TestType).TestField = "some-value"
			return nil
		},
	})
	inputRequest := admissionv1.AdmissionRequest{
		UID:       types.UID("abc"),
		Operation: admissionv1.Create,
		Kind: metav1.GroupVersionKind{
			Group:   "testgroup.testing.cert-manager.io",
			Version: "v1",
			Kind:    "TestType",
		},
		RequestKind: &metav1.GroupVersionKind{
			Group:   "testgroup.testing.cert-manager.io",
			Version: "v1",
			Kind:    "TestType",
		},
		Object: runtime.RawExtension{
			Raw: []byte(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v1",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	},
	"testFieldImmutable": "abc",
	"testDefaultingField": "set-to-something"
}
`),
		},
	}
	expectedResponse := admissionv1.AdmissionResponse{
		UID:     types.UID("abc"),
		Allowed: true,
		Patch: responseForOperations(
			jsonpatch.JsonPatchOperation{
				Operation: "add",
				Path:      "/testField",
				Value:     "some-value",
			},
			jsonpatch.JsonPatchOperation{
				Operation: "add",
				Path:      "/testFieldPtr",
				Value:     "teststr",
			},
		),
		PatchType: &jsonPatchType,
	}

	resp := rh.Mutate(context.TODO(), &inputRequest)
	if !reflect.DeepEqual(&expectedResponse, resp) {
		t.Errorf("Response was not as expected: %v", diff.ObjectGoPrintSideBySide(&expectedResponse, resp))
	}
}

func TestRequestHandler_MutateAppliesDefaultsInRequestVersion(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)

	rh := admission.NewRequestHandler(scheme, nil, testMutator{
		handles: true,
		mutate: func(_ context.Context, _ admissionv1.AdmissionRequest, obj runtime.Object) error {
			// Doesn't do anything as the request handler itself will generate patches to apply
			// defaults instead of it being applied within a particular admission plugin.
			return nil
		},
	})
	inputRequest := admissionv1.AdmissionRequest{
		UID:       types.UID("abc"),
		Operation: admissionv1.Create,
		Kind: metav1.GroupVersionKind{
			Group:   "testgroup.testing.cert-manager.io",
			Version: "v1",
			Kind:    "TestType",
		},
		RequestKind: &metav1.GroupVersionKind{
			Group: "testgroup.testing.cert-manager.io",
			// Because the API version is v2, we expect the `testDefaultingField` field to be set to `set-in-v2`.
			// In v1, the field will be set to `set-in-v1`.
			Version: "v2",
			Kind:    "TestType",
		},
		Object: runtime.RawExtension{
			Raw: []byte(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v1",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	},
	"testField": "set-to-something-to-avoid-extra-mutations",
	"testFieldImmutable": "set-to-something-to-avoid-extra-mutations",
	"testFieldPtr": "set-to-something-to-avoid-extra-mutations"
}
`),
		},
	}
	expectedResponse := admissionv1.AdmissionResponse{
		UID:     types.UID("abc"),
		Allowed: true,
		Patch: responseForOperations(
			jsonpatch.JsonPatchOperation{
				Operation: "add",
				Path:      "/testDefaultingField",
				Value:     "set-in-v2",
			},
		),
		PatchType: &jsonPatchType,
	}

	resp := rh.Mutate(context.TODO(), &inputRequest)
	if !reflect.DeepEqual(&expectedResponse, resp) {
		t.Errorf("Response was not as expected: %v", diff.ObjectGoPrintSideBySide(&expectedResponse, resp))
	}
}

// Tests to ensure that the RequestHandler skips running mutation handlers
// that do not return true to Handles, but still applies scheme based defaulting.
func TestRequestHandler_MutateSkipsMutation(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)

	rh := admission.NewRequestHandler(scheme, nil, testMutator{
		handles: false,
	})
	inputRequest := admissionv1.AdmissionRequest{
		UID:       types.UID("abc"),
		Operation: admissionv1.Create,
		Kind: metav1.GroupVersionKind{
			Group:   "testgroup.testing.cert-manager.io",
			Version: "v1",
			Kind:    "TestType",
		},
		RequestKind: &metav1.GroupVersionKind{
			Group:   "testgroup.testing.cert-manager.io",
			Version: "v1",
			Kind:    "TestType",
		},
		Object: runtime.RawExtension{
			Raw: []byte(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v1",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	},
	"testField": "some-value",
	"testFieldImmutable": "abc",
	"testDefaultingField": "set-to-something"
}
`),
		},
	}
	expectedResponse := admissionv1.AdmissionResponse{
		UID:     types.UID("abc"),
		Allowed: true,
		Patch: responseForOperations(
			jsonpatch.JsonPatchOperation{
				Operation: "add",
				Path:      "/testFieldPtr",
				Value:     "teststr",
			},
		),
		PatchType: &jsonPatchType,
	}

	resp := rh.Mutate(context.TODO(), &inputRequest)
	if !reflect.DeepEqual(&expectedResponse, resp) {
		t.Errorf("Response was not as expected: %v", diff.ObjectGoPrintSideBySide(&expectedResponse, resp))
	}
}

func TestRequestHandler_ValidateReturnsErrorsAndWarnings(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)

	rh := admission.NewRequestHandler(scheme, testValidator{
		handles:  true,
		warnings: []string{"a warning"},
		err:      fmt.Errorf("some synthetic error"),
	}, nil)
	inputRequest := admissionv1.AdmissionRequest{
		UID:       types.UID("abc"),
		Operation: admissionv1.Create,
		Kind: metav1.GroupVersionKind{
			Group:   "testgroup.testing.cert-manager.io",
			Version: "v1",
			Kind:    "TestType",
		},
		RequestKind: &metav1.GroupVersionKind{
			Group:   "testgroup.testing.cert-manager.io",
			Version: "v1",
			Kind:    "TestType",
		},
		Object: runtime.RawExtension{
			Raw: []byte(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v1",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc"
	}
}
`),
		},
	}
	expectedResponse := admissionv1.AdmissionResponse{
		UID:     types.UID("abc"),
		Allowed: false,
		Result: &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: "some synthetic error",
			Reason:  metav1.StatusReasonNotAcceptable,
			Code:    http.StatusNotAcceptable,
		},
		Warnings: []string{"a warning"},
	}

	resp := rh.Validate(context.TODO(), &inputRequest)
	if !reflect.DeepEqual(&expectedResponse, resp) {
		t.Errorf("Response was not as expected: %v", diff.ObjectGoPrintSideBySide(&expectedResponse, resp))
	}
}

func responseForOperations(ops ...jsonpatch.JsonPatchOperation) []byte {
	b, err := json.Marshal(ops)
	if err != nil {
		// this shouldn't ever be reached
		panic("failed to encode JSON test data")
	}
	return b
}

type testValidator struct {
	handles  bool
	warnings []string
	err      error
}

var _ admission.ValidationInterface = testValidator{}

func (t testValidator) Handles(operation admissionv1.Operation) bool {
	return t.handles
}

func (t testValidator) Validate(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (warnings []string, err error) {
	return t.warnings, t.err
}

type testMutator struct {
	handles bool
	mutate  func(_ context.Context, _ admissionv1.AdmissionRequest, obj runtime.Object) error
}

var _ admission.MutationInterface = testMutator{}

func (t testMutator) Handles(_ admissionv1.Operation) bool {
	return t.handles
}

func (t testMutator) Mutate(ctx context.Context, req admissionv1.AdmissionRequest, obj runtime.Object) error {
	return t.mutate(ctx, req, obj)
}
