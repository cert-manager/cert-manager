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

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
)

func TestEnabledControllers(t *testing.T) {
	tests := map[string]struct {
		controllers []string
		expEnabled  sets.String
	}{
		"if no controllers enabled, return empty": {
			controllers: []string{},
			expEnabled:  sets.NewString(),
		},
		"if some controllers enabled, return list": {
			controllers: []string{"foo", "bar"},
			expEnabled:  sets.NewString("foo", "bar"),
		},
		"if some controllers enabled, one then disabled, return list without disabled": {
			controllers: []string{"foo", "bar", "-foo"},
			expEnabled:  sets.NewString("bar"),
		},
		"if all default controllers enabled, return all default controllers": {
			controllers: []string{"*"},
			expEnabled:  sets.NewString(defaultEnabledControllers...),
		},
		"if all controllers enabled, some diabled, return all controllers with disabled": {
			controllers: []string{"*", "-clusterissuers", "-issuers"},
			expEnabled:  sets.NewString(defaultEnabledControllers...).Delete("clusterissuers", "issuers"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			o := ControllerOptions{
				controllers: test.controllers,
			}

			got := o.EnabledControllers()
			if !got.Equal(test.expEnabled) {
				t.Errorf("got unexpected enabled, exp=%s got=%s",
					test.expEnabled, got)
			}
		})
	}
}
