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

package resourcevalidation

import (
	"fmt"
	"reflect"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cert-manager/cert-manager/internal/apis/certmanager"
	"github.com/cert-manager/cert-manager/pkg/webhook/admission"
)

var (
	sampleMetaGVR = metav1.GroupVersionResource{
		Group:    "sample-group",
		Version:  "sample-version",
		Resource: "sample-resource",
	}
)

func TestResourceValidation(t *testing.T) {
	tests := map[string]struct {
		req         admissionv1.AdmissionRequest
		oldObj, obj runtime.Object

		expectedWarnings []string
		expectedError    error
	}{
		"does nothing when the requested resource has no registered validation functions": {
			req: admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				Resource:  sampleMetaGVR,
			},
		},
		"does nothing for non-create or update operations": {
			req: admissionv1.AdmissionRequest{
				Operation: admissionv1.Connect,
				Resource: metav1.GroupVersionResource{
					Group:    "cert-manager.io",
					Version:  "v1",
					Resource: "certificates",
				},
			},
		},
		"rejects requests where Resource is unset instead of skipping validation": {
			req: admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
			},
			expectedError: admission.ErrResourceUnset,
		},
		"rejects a Create object that does not match the resource's expected type": {
			req: admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				Resource: metav1.GroupVersionResource{
					Group:    "cert-manager.io",
					Version:  "v1",
					Resource: "certificates",
				},
			},
			obj:           &certmanager.CertificateRequest{},
			expectedError: fmt.Errorf("internal error: object in admission request is not of type *certmanager.Certificate"),
		},
		"rejects an Update object that does not match the resource's expected type": {
			req: admissionv1.AdmissionRequest{
				Operation: admissionv1.Update,
				Resource: metav1.GroupVersionResource{
					Group:    "cert-manager.io",
					Version:  "v1",
					Resource: "certificates",
				},
			},
			oldObj:        &certmanager.Certificate{},
			obj:           &certmanager.CertificateRequest{},
			expectedError: fmt.Errorf("internal error: object in admission request is not of type *certmanager.Certificate"),
		},
		"rejects an Update oldObject that does not match the resource's expected type": {
			req: admissionv1.AdmissionRequest{
				Operation: admissionv1.Update,
				Resource: metav1.GroupVersionResource{
					Group:    "cert-manager.io",
					Version:  "v1",
					Resource: "certificates",
				},
			},
			oldObj:        &certmanager.CertificateRequest{},
			obj:           &certmanager.Certificate{},
			expectedError: fmt.Errorf("internal error: oldObject in admission request is not of type *certmanager.Certificate"),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := NewPlugin().(*resourceValidation)
			warnings, err := p.Validate(t.Context(), test.req, test.oldObj, test.obj)
			compareErrors(t, test.expectedError, err)
			if !reflect.DeepEqual(test.expectedWarnings, warnings) {
				t.Errorf("unexpected warnings. exp=%v, got=%v", test.expectedWarnings, warnings)
			}
		})
	}
}

func compareErrors(t *testing.T, exp, act error) {
	if exp == nil && act == nil {
		return
	}
	if exp == nil && act != nil ||
		exp != nil && act == nil ||
		exp.Error() != act.Error() {
		t.Errorf("error not as expected. exp=%v, act=%v", exp, act)
	}
}
