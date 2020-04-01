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

package testing

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// PathForCRD attempts to find a path to the named CRD.
// The 'name' is the name of the resource contained within the CRD as denoted
// by the filename, e.g. 'foobar' would find a CRD with a filename containing
// the word 'foobar'.
func PathForCRD(t *testing.T, name string) string {
	dir := CRDDirectory(t)
	path := filepath.Join(dir, fmt.Sprintf("crd-%s.templated.yaml", name))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() {
		t.Fatalf("expected to find a file when finding path for CRD, but found a directory")
	}
	return path
}

func CRDDirectory(t *testing.T) string {
	runfiles := os.Getenv("RUNFILES_DIR")
	if runfiles == "" {
		t.Fatalf("integration tests can only run within 'bazel test' environment")
	}
	path := filepath.Join(runfiles, "com_github_jetstack_cert_manager", "deploy", "crds")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("expected to find a directory, but found a file")
	}
	return path
}
