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

package apideprecation

import (
	"context"
	"reflect"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAPIDeprecation(t *testing.T) {
	tests := map[string]struct {
		req      *admissionv1.AdmissionRequest
		warnings []string
	}{
		"should print warnings for all non-v1 cert-manager.io types": {
			req: &admissionv1.AdmissionRequest{
				RequestResource: &metav1.GroupVersionResource{
					Group:    "cert-manager.io",
					Version:  "something-not-v1",
					Resource: "somethings",
				},
			},
			warnings: []string{"somethings.cert-manager.io/something-not-v1 is deprecated in v1.4+, unavailable in v1.6+; use somethings.cert-manager.io/v1"},
		},
		"should print warnings for all non-v1 acme.cert-manager.io types": {
			req: &admissionv1.AdmissionRequest{
				RequestResource: &metav1.GroupVersionResource{
					Group:    "acme.cert-manager.io",
					Version:  "something-not-v1",
					Resource: "somethings",
				},
			},
			warnings: []string{"somethings.acme.cert-manager.io/something-not-v1 is deprecated in v1.4+, unavailable in v1.6+; use somethings.acme.cert-manager.io/v1"},
		},
		"should not print warnings for non-v1 types in other groups": {
			req: &admissionv1.AdmissionRequest{
				RequestResource: &metav1.GroupVersionResource{
					Group:    "some-other-group-name",
					Version:  "something-not-v1",
					Resource: "somethings",
				},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := NewPlugin().(*apiDeprecation)
			warnings, err := p.Validate(context.Background(), *test.req, nil, nil)
			if err != nil {
				t.Errorf("unexpected error")
			}
			if !reflect.DeepEqual(warnings, test.warnings) {
				t.Errorf("unexpected warnings, exp=%q, got=%q", test.warnings, warnings)
			}
		})
	}
}
