/*
Copyright 2026 The cert-manager Authors.

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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/pkg/webhook/admission"
)

func TestIsResourceUnset(t *testing.T) {
	tests := map[string]struct {
		gvr  metav1.GroupVersionResource
		want bool
	}{
		"zero value is unset": {
			gvr:  metav1.GroupVersionResource{},
			want: true,
		},
		"fully populated GVR is set": {
			gvr: metav1.GroupVersionResource{
				Group:    "cert-manager.io",
				Version:  "v1",
				Resource: "certificaterequests",
			},
			want: false,
		},
		"only Resource populated is still set": {
			gvr: metav1.GroupVersionResource{
				Resource: "certificaterequests",
			},
			want: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := admission.IsResourceUnset(test.gvr); got != test.want {
				t.Errorf("IsResourceUnset(%+v) = %v, want %v", test.gvr, got, test.want)
			}
		})
	}
}
