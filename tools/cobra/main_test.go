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

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRun(t *testing.T) {
	rootDir, err := os.MkdirTemp(os.TempDir(), "cert-manager-cobra")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(rootDir); err != nil {
			t.Fatal(err)
		}
	}()

	tests := map[string]struct {
		input   []string
		expDirs []string
		expErr  bool
	}{
		"if no arguments given should error": {
			input:  []string{"cobra"},
			expErr: true,
		},
		"if two arguments given should error": {
			input:  []string{"cobra", "foo", "bar"},
			expErr: true,
		},
		"if directory given, should write docs": {
			input:   []string{"cobra", filepath.Join(rootDir, "foo")},
			expDirs: []string{"foo/ca-injector", "foo/cert-manager-controller", "foo/cmctl"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := run(test.input)
			if test.expErr != (err != nil) {
				t.Errorf("got unexpected error, exp=%t got=%v",
					test.expErr, err)
			}

			for _, dir := range test.expDirs {
				if _, err := os.Stat(filepath.Join(rootDir, dir)); err != nil {
					t.Errorf("stat error on expected directory: %s", err)
				}
			}
		})
	}
}
