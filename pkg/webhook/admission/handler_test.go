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
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
)

var allOperations = []admissionv1.Operation{admissionv1.Update, admissionv1.Create, admissionv1.Connect, admissionv1.Delete}

func TestHandler(t *testing.T) {
	h := NewHandler(admissionv1.Create)
	for _, op := range allOperations {
		handles := h.Handles(op)
		if op == admissionv1.Create && !handles {
			t.Error("expected handler to handle CREATE but it did not")
		}
		if op != admissionv1.Create && handles {
			t.Errorf("did not expect handler to handle %q", op)
		}
	}
}
