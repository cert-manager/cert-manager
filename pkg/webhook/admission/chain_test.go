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
	"fmt"
	"reflect"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cert-manager/cert-manager/pkg/webhook/admission"
)

func TestChainHandles(t *testing.T) {
	pc := admission.PluginChain([]admission.Interface{
		// this handler should be called
		validatingImplementation{handles: handles(true).Handles},
		validatingImplementation{handles: handles(false).Handles},
	})
	// actual operation passed here does not matter
	if !pc.Handles(admissionv1.Create) {
		t.Errorf("expected handler to handle this request but it did not")
	}
}

func TestChainDoesntHandle(t *testing.T) {
	pc := admission.PluginChain([]admission.Interface{
		// this handler should be called
		validatingImplementation{handles: handles(false).Handles},
		validatingImplementation{handles: handles(false).Handles},
	})
	// actual operation passed here does not matter
	if pc.Handles(admissionv1.Create) {
		t.Errorf("expected handler to not handle this message but it did")
	}
}

func TestChainValidate(t *testing.T) {
	validateCalled := false
	pc := admission.PluginChain([]admission.Interface{
		// this handler should be called
		validatingImplementation{
			handles: handles(true).Handles,
			validate: func(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) ([]string, error) {
				validateCalled = true
				return []string{"warning1", "warning2"}, nil
			},
		},
		// it's not expected that this handler will be called
		validatingImplementation{
			// this handler explicitly does not handle the call
			handles: handles(false).Handles,
			validate: func(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) ([]string, error) {
				t.Errorf("second validation function was unexpectedly called during a validate call")
				return []string{"warning3", "warning4"}, nil
			},
		},
		// this handler should be called
		validatingImplementation{
			handles: handles(true).Handles,
			validate: func(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) ([]string, error) {
				return []string{"warning5"}, nil
			},
		},
		mutatingImplementation{
			handles: handles(true).Handles,
			mutate: func(ctx context.Context, request admissionv1.AdmissionRequest, obj *unstructured.Unstructured) error {
				t.Errorf("mutate function was unexpectedly called during a validate call")
				return fmt.Errorf("unexpected error")
			},
		},
	})
	warnings, err := pc.Validate(context.Background(), admissionv1.AdmissionRequest{}, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !validateCalled {
		t.Errorf("validation function was not called")
	}
	if !reflect.DeepEqual(warnings, []string{"warning1", "warning2", "warning5"}) {
		t.Errorf("got unexpected list of warnings: %v", warnings)
	}
}

func TestChainValidate_Fails(t *testing.T) {
	pc := admission.PluginChain([]admission.Interface{
		// this handler should be called
		validatingImplementation{
			handles: handles(true).Handles,
			validate: func(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) ([]string, error) {
				return []string{"warning1", "warning2"}, fmt.Errorf("error")
			},
		},
		// this handler should be called
		validatingImplementation{
			handles: handles(true).Handles,
			validate: func(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) ([]string, error) {
				return []string{"warning5"}, nil
			},
		},
	})
	warnings, err := pc.Validate(context.Background(), admissionv1.AdmissionRequest{}, nil, nil)
	if err == nil {
		t.Errorf("didn't get an error when one was expected")
	}
	if !reflect.DeepEqual(warnings, []string{"warning1", "warning2", "warning5"}) {
		t.Errorf("got unexpected list of warnings: %v", warnings)
	}
}

func TestChainMutate(t *testing.T) {
	pc := admission.PluginChain([]admission.Interface{
		// this handler should be called
		mutatingImplementation{
			handles: handles(true).Handles,
			mutate: func(ctx context.Context, request admissionv1.AdmissionRequest, obj *unstructured.Unstructured) error {
				return unstructured.SetNestedField(obj.Object, "testvalue", "testField1")
			},
		},
		// this handler should not be called
		mutatingImplementation{
			handles: handles(false).Handles,
			mutate: func(ctx context.Context, request admissionv1.AdmissionRequest, obj *unstructured.Unstructured) error {
				return unstructured.SetNestedField(obj.Object, "hopefully-not-set", "testField2")
			},
		},
	})
	tt := &unstructured.Unstructured{Object: map[string]any{}}
	err := pc.Mutate(context.Background(), admissionv1.AdmissionRequest{}, tt)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if val, ok, err := unstructured.NestedString(tt.Object, "testField1"); err != nil || !ok || val != "testvalue" {
		t.Errorf("expected tt.testField1=testvalue but got %q", tt.Object)
	}
	if val, ok, err := unstructured.NestedString(tt.Object, "testField2"); err != nil || ok || val != "" {
		t.Errorf("expected tt.testField2 to not be set, but got %q", tt.Object)
	}
}

func TestChainMutate_Fails(t *testing.T) {
	pc := admission.PluginChain([]admission.Interface{
		// this handler should be called and should error
		mutatingImplementation{
			handles: handles(true).Handles,
			mutate: func(ctx context.Context, request admissionv1.AdmissionRequest, obj *unstructured.Unstructured) error {
				return fmt.Errorf("error")
			},
		},
	})
	err := pc.Mutate(context.Background(), admissionv1.AdmissionRequest{}, &unstructured.Unstructured{Object: map[string]any{}})
	if err == nil {
		t.Errorf("expected error but got none")
	}
}
