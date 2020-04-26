/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package renew

import (
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	tests := map[string]struct {
		options *Options
		args    []string
		expErr  bool
	}{
		"If there are arguments, as well as label selector, error": {
			options: &Options{
				LabelSelector: "foo=bar",
			},
			args:   []string{"abc"},
			expErr: true,
		},
		"If there are all certificates selected, as well as label selector, error": {
			options: &Options{
				LabelSelector: "foo=bar",
				All:           true,
			},
			args:   []string{""},
			expErr: true,
		},
		"If there are all certificates selected, as well as arguments, error": {
			options: &Options{
				All: true,
			},
			args:   []string{"abc"},
			expErr: true,
		},
		"If waiting, and timeout is less than poll time, but not zero, error": {
			options: &Options{
				Timeout: time.Second,
				Wait:    true,
			},
			expErr: true,
		},
		"If waiting, and timeout is less than poll time, but zero, don't error": {
			options: &Options{
				Timeout: 0,
				Wait:    true,
			},
			expErr: false,
		},
		"If not waiting, and timeout is less than poll time, but not zero, don't error": {
			options: &Options{
				Timeout: time.Second,
				Wait:    false,
			},
			expErr: false,
		},
		"If all certificates in all namespaces selected, don't error": {
			options: &Options{
				All:           true,
				AllNamespaces: true,
			},
			expErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.options.Validate(test.args)

			if test.expErr != (err != nil) {
				t.Errorf("expected error=%t got=%v",
					test.expErr, err)
			}
		})
	}
}
