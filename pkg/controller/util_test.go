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

package controller

import (
	"reflect"
	"testing"
)

func TestBuildAnnotationsToCopy(t *testing.T) {
	tests := map[string]struct {
		allAnnotations map[string]string
		prefixes       []string
		want           map[string]string
	}{
		"no annotations should be copied": {
			allAnnotations: map[string]string{"foo": "bar", "bar": "bat"},
			prefixes:       []string{},
			want:           make(map[string]string),
		},
		"all annotations should be copied": {
			allAnnotations: map[string]string{"foo": "bar", "bar": "bat"},
			prefixes:       []string{"*"},
			want:           map[string]string{"foo": "bar", "bar": "bat"},
		},
		"all except some should be copied": {
			allAnnotations: map[string]string{"foo": "bar", "foo.io/thing": "bar", "foo.io/anotherthing": "bat", "bar": "bat"},
			prefixes:       []string{"*", "-foo.io/"},
			want:           map[string]string{"foo": "bar", "bar": "bat"},
		},
		"only some should be copied": {
			allAnnotations: map[string]string{
				"foo": "bar", "foo.io/thing": "bar", "foo.io/anotherthing": "bat", "bar": "bat",
			},
			prefixes: []string{"foo.io/"},
			want:     map[string]string{"foo.io/thing": "bar", "foo.io/anotherthing": "bat"},
		},
		"some annotations have been specified, but none found on the cert": {
			allAnnotations: map[string]string{},
			prefixes:       []string{"*", "-foo.io/"},
			want:           map[string]string{},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := BuildAnnotationsToCopy(test.allAnnotations, test.prefixes); !reflect.DeepEqual(got, test.want) {
				t.Errorf("BuildAnnotationsToCopy() = %+#v, want %+#v", got, test.want)
			}
		})
	}
}
