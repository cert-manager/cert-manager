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

package admission

import (
	"context"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// Interface is the base admission interface
type Interface interface {
	Handles(admissionv1.Operation) bool
}

// ValidationInterface defines an admission handler that validates requests.
// It may not perform any kind of mutation.
type ValidationInterface interface {
	Interface

	Validate(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (warnings []string, err error)
}

// MutationInterface defines an admission handler that validates requests.
// It may not perform any kind of mutation.
type MutationInterface interface {
	Interface

	Mutate(ctx context.Context, request admissionv1.AdmissionRequest, obj *unstructured.Unstructured) (err error)
}
