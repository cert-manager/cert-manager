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
	"context"

	admissionv1 "k8s.io/api/admission/v1"
)

type ValidatingAdmissionHook interface {
	// Validate is called to decide whether to accept the admission request. The returned AdmissionResponse
	// must not use the Patch field.
	Validate(ctx context.Context, admissionSpec *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse
}

type MutatingAdmissionHook interface {
	// Mutate is called to decide whether to accept the admission request. The returned AdmissionResponse may
	// use the Patch field to mutate the object from the passed AdmissionRequest.
	Mutate(ctx context.Context, admissionSpec *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse
}
