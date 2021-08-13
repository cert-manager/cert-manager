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

package util

import (
	"os"
	"path/filepath"
)

// GetTestPath returns the path for bazel golang test dependencies
// These dependencies are set in the go_test data attribute in the BUILD.bazel file
// see: https://github.com/bazelbuild/rules_go/blob/master/go/core.rst#go_test -> data attribute
func GetTestPath(path ...string) string {
	return filepath.Join(append([]string{os.Getenv("RUNFILES_DIR"), "com_github_jetstack_cert_manager"}, path...)...)
}
