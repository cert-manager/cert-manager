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

package apiserver

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/cert-manager/cert-manager/internal/test/paths"
)

// setEnvTestEnv configures environment variables for controller-runtime's
// 'envtest' package.
func setUpEnvTestEnv() {
	maybeSetEnv("TEST_ASSET_ETCD", "etcd")
	maybeSetEnv("TEST_ASSET_KUBE_APISERVER", "kube-apiserver")
	maybeSetEnv("TEST_ASSET_KUBECTL", "kubectl")
}

func maybeSetEnv(key, bin string) {
	if os.Getenv(key) != "" {
		return
	}
	p, err := getPath(bin)
	if err != nil {
		panic(fmt.Sprintf(`Failed to find integration test dependency %q.
Either re-run this test or set the %s environment variable.`, bin, key))
	}
	os.Setenv(key, p)
}

func getPath(name string) (string, error) {
	// check in _bin/tools for a file provisioned using make
	binToolsPath := filepath.Join(paths.BinToolsDir, name)
	p, err := exec.LookPath(binToolsPath)
	if err == nil {
		return p, nil
	}

	// Otherwise check the users PATH
	p, err = exec.LookPath(name)
	if err == nil {
		return p, nil
	}

	return "", fmt.Errorf("failed to find %q in bazel-bin, bin/tools, or in $PATH", name)
}
