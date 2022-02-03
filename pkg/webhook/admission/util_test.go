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

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cert-manager/cert-manager/pkg/webhook/admission"
)

type handles bool

func (h handles) Handles(admissionv1.Operation) bool {
	return bool(h)
}

type validatingImplementation struct {
	handles  func(admissionv1.Operation) bool
	validate func(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) ([]string, error)
}

func (v validatingImplementation) Handles(operation admissionv1.Operation) bool {
	return v.handles(operation)
}

func (v validatingImplementation) Validate(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (warnings []string, err error) {
	return v.validate(ctx, request, oldObj, obj)
}

var _ admission.ValidationInterface = &validatingImplementation{}

type mutatingImplementation struct {
	handles func(admissionv1.Operation) bool
	mutate  func(ctx context.Context, request admissionv1.AdmissionRequest, obj runtime.Object) error
}

func (v mutatingImplementation) Handles(operation admissionv1.Operation) bool {
	return v.handles(operation)
}

func (v mutatingImplementation) Mutate(ctx context.Context, request admissionv1.AdmissionRequest, obj runtime.Object) error {
	return v.mutate(ctx, request, obj)
}

var _ admission.MutationInterface = &mutatingImplementation{}
