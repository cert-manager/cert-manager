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
	"context"
	"reflect"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

var (
	sampleSchemaGVR = schema.GroupVersionResource{
		Group:    "sample-group",
		Version:  "sample-version",
		Resource: "sample-resource",
	}
	sampleMetaGVR = metav1.GroupVersionResource{
		Group:    sampleSchemaGVR.Group,
		Version:  sampleSchemaGVR.Version,
		Resource: sampleSchemaGVR.Resource,
	}

	alwaysFailsCreateFunc = func(a *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, []string) {
		panic("create function not expected to be called")
	}
	alwaysFailsUpdateFunc = func(a *admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (field.ErrorList, []string) {
		panic("update function not expected to be called")
	}

	alwaysFailsValidationPair = validationPair{
		create: alwaysFailsCreateFunc,
		update: alwaysFailsUpdateFunc,
	}
)

func TestResourceValidation(t *testing.T) {
	tests := map[string]struct {
		mapping     map[schema.GroupVersionResource]validationPair
		req         admissionv1.AdmissionRequest
		oldObj, obj runtime.Object

		expectedWarnings []string
		expectedError    error
	}{
		"should not perform any validation if no validation functions are registered": {
			mapping: map[schema.GroupVersionResource]validationPair{},
			req: admissionv1.AdmissionRequest{
				Operation:       admissionv1.Create,
				RequestResource: &sampleMetaGVR,
			},
		},
		"does nothing for non-create or update operations": {
			mapping: map[schema.GroupVersionResource]validationPair{
				sampleSchemaGVR: alwaysFailsValidationPair,
			},
			req: admissionv1.AdmissionRequest{
				Operation:       admissionv1.Connect,
				RequestResource: &sampleMetaGVR,
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := NewPlugin().(*resourceValidation)
			p.validationMappings = test.mapping
			warnings, err := p.Validate(context.Background(), test.req, test.oldObj, test.obj)
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
