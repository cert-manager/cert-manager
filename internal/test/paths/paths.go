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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

var (
	_, b, _, _ = runtime.Caller(0)

	// ModuleRootDir is the filesystem path to the root of the repository.
	ModuleRootDir = filepath.Join(filepath.Dir(b), "../../..")

	// BinDir is the filesystem path of the bin directory which is populated using
	// Makefile commands
	BinDir = filepath.Join(ModuleRootDir, "bin")

	// BinToolsDir is the filesystem path of the bin/tools directory which can for
	// example be populated by `make -f make/Makefile integration-test-tools`.
	BinToolsDir = filepath.Join(BinDir, "tools")

	// BinCRDDir is the filesystem path of templated CRDs created by Makefile commands
	BinCRDDir = filepath.Join(BinDir, "yaml", "templated-crds")

	// BazelBinDir is the filesystem path to the bazel-bin directory within the
	// root of the repository.
	// This will not be accessible when running within the bazel sandbox, but
	// is useful for reading bazel files when running commands with `go test`.
	BazelBinDir = filepath.Join(ModuleRootDir, "bazel-bin")
)

// PathForCRD attempts to find a path to the named CRD.
// The 'name' is the name of the resource contained within the CRD as denoted
// by the filename, e.g. 'foobar' would find a CRD with a filename containing
// the word 'foobar'.
func PathForCRD(t *testing.T, name string) string {
	dir, err := CRDDirectory()
	if err != nil {
		t.Fatalf("failed to find CRD directory: %s", err)
	}

	path := filepath.Join(dir, fmt.Sprintf("crd-%s.templated.yaml", name))

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if info.IsDir() {
		t.Fatalf("expected to find a file when finding path for CRD, but found a directory %q", path)
	}

	return path
}

// CRDDirectory returns the directory containing CRDs, if it can be found.
func CRDDirectory() (string, error) {
	var dir string
	var err error

	dir, err = makefileCRDDirectory()
	if err == nil {
		return dir, nil
	}

	dir, err = bazelCRDDirectory()
	if err == nil {
		return dir, nil
	}

	return "", fmt.Errorf("failed to find CRDs provisioned by either bazel (under %q) or by make (at %q)", BazelBinDir, BinCRDDir)
}

func bazelCRDDirectory() (string, error) {
	bazelDir := BazelBinDir

	path := filepath.Join(bazelDir, "deploy", "crds")

	// prefer RUNFILES_DIR if set
	runfiles := os.Getenv("RUNFILES_DIR")
	if runfiles != "" {
		path = filepath.Join(runfiles, "com_github_jetstack_cert_manager", "deploy", "crds")
	}

	err := checkCRDDirectory(path)
	if err != nil {
		return "", err
	}

	return path, nil
}

func makefileCRDDirectory() (string, error) {
	path := BinCRDDir

	err := checkCRDDirectory(path)
	if err != nil {
		return "", err
	}

	return path, nil
}

func checkCRDDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return fmt.Errorf("expected %q to be a directory, but found a file", path)
	}

	return nil
}
