/*
Copyright 2022 The cert-manager Authors.

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

package paths

import (
	"path/filepath"
	"runtime"
)

var (
	_, b, _, _ = runtime.Caller(0)

	// ModuleRootDir is the filesystem path to the root of the repository.
	ModuleRootDir = filepath.Join(filepath.Dir(b), "../../..")

	// BazelBinDir is the filesystem path to the bazel-bin directory within the
	// root of the repository.
	// This will not be accessible when running within the bazel sandbox, but
	// is useful for reading bazel files when running commands with `go test`.
	BazelBinDir = filepath.Join(ModuleRootDir, "bazel-bin")
)
