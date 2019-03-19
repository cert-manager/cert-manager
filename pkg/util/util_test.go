/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package util

import (
	"testing"
)

func TestEqualUnsorted(t *testing.T) {
	type testT struct {
		desc  string
		s1    []string
		s2    []string
		equal bool
	}
	tests := []testT{
		{
			desc:  "equal but out of order slices should be equal",
			s1:    []string{"a", "b", "c"},
			s2:    []string{"b", "a", "c"},
			equal: true,
		},
		{
			desc:  "non-equal but ordered slices should not be equal",
			s1:    []string{"a", "b"},
			s2:    []string{"a", "b", "c"},
			equal: false,
		},
		{
			desc:  "non-equal but ordered slices should not be equal",
			s1:    []string{"a", "b", "c"},
			s2:    []string{"a", "b"},
			equal: false,
		},
		{
			desc:  "equal and ordered slices should be equal",
			s1:    []string{"a", "b", "c"},
			s2:    []string{"a", "b", "c"},
			equal: true,
		},
		{
			desc:  "unequal lists of the same length are not equal",
			s1:    []string{"example.com"},
			s2:    []string{"notexample.com"},
			equal: false,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(test testT) func(*testing.T) {
			return func(t *testing.T) {
				if actual := EqualUnsorted(test.s1, test.s2); actual != test.equal {
					t.Errorf("equalUnsorted(%+v, %+v) = %t, but expected %t", test.s1, test.s2, actual, test.equal)
				}
			}
		}(test))
	}
}

func TestContains(t *testing.T) {
	type testT struct {
		desc  string
		slice []string
		value string
		equal bool
	}
	tests := []testT{
		{
			desc:  "slice containing value",
			slice: []string{"a", "b", "c"},
			value: "a",
			equal: true,
		},
		{
			desc:  "slice not containing value",
			slice: []string{"a", "b", "c"},
			value: "x",
			equal: false,
		},
		{
			desc:  "empty slice",
			slice: []string{},
			value: "x",
			equal: false,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(test testT) func(*testing.T) {
			return func(t *testing.T) {
				if actual := Contains(test.slice, test.value); actual != test.equal {
					t.Errorf("Contains(%+v, %+v) = %t, but expected %t", test.slice, test.value, actual, test.equal)
				}
			}
		}(test))
	}
}
