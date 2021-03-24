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

package options

import "testing"

func TestControllerEnabled(t *testing.T) {
	tests := map[string]struct {
		enabled    []string
		name       string
		expEnabled bool
	}{
		"if no controllers enabled, return false": {
			enabled:    []string{},
			name:       "foo",
			expEnabled: false,
		},
		"if different controllers enabled, return false": {
			enabled:    []string{"123", "456"},
			name:       "foo",
			expEnabled: false,
		},
		"if controller enabled, return true": {
			enabled:    []string{"123", "foo", "456"},
			name:       "foo",
			expEnabled: true,
		},
		"if all controllers enabled, return true": {
			enabled:    []string{"*"},
			name:       "foo",
			expEnabled: true,
		},
		"if all controllers enabled but foo diabled, return false": {
			enabled:    []string{"*", "-foo"},
			name:       "foo",
			expEnabled: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			o := ControllerOptions{
				EnabledControllers: test.enabled,
			}

			got := o.ControllerEnabled(test.name)
			if got != test.expEnabled {
				t.Errorf("got unexpected enabled, exp=%t got=%t",
					test.expEnabled, got)
			}
		})
	}
}
