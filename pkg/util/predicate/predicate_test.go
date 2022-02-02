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

package predicate

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func TestFuncs_Evaluate(t *testing.T) {
	falseFunc := func(_ runtime.Object) bool {
		return false
	}
	trueFunc := func(_ runtime.Object) bool {
		return true
	}
	tests := map[string]struct {
		funcs    Funcs
		expected bool
	}{
		"returns false if one returns false": {
			funcs:    Funcs{falseFunc},
			expected: false,
		},
		"returns false if at least one returns false": {
			funcs:    Funcs{falseFunc, trueFunc},
			expected: false,
		},
		"returns false if at least one returns false (reversed)": {
			funcs:    Funcs{trueFunc, falseFunc},
			expected: false,
		},
		"returns true if all return true": {
			funcs:    Funcs{trueFunc, trueFunc},
			expected: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := test.funcs.Evaluate(nil)
			if got != test.expected {
				t.Errorf("unexpected response: got=%t, exp=%t", got, test.expected)
			}
		})
	}
}

func TestExtractResourceName(t *testing.T) {
	expectedValue := "expected-value"
	called := false

	fn := ExtractResourceName(func(s string) Func {
		called = true
		if s != expectedValue {
			t.Errorf("function called with unexpected value: got=%s, exp=%s", s, expectedValue)
		}
		return nil
	})

	obj := &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Name: expectedValue}}
	fn(obj)
	if !called {
		t.Fatal("unexpected error - function not called!")
	}
}
