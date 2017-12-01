/*
Copyright 2015 The Kubernetes Authors.
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

package e2e

import (
	"os"
	"os/exec"
	"testing"

	"github.com/golang/glog"
	"github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/config"
	"github.com/onsi/gomega"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/jetstack/cert-manager/pkg/logs"
	_ "github.com/jetstack/cert-manager/test/e2e/certificate"
	_ "github.com/jetstack/cert-manager/test/e2e/clusterissuer"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	_ "github.com/jetstack/cert-manager/test/e2e/ingress"
	_ "github.com/jetstack/cert-manager/test/e2e/issuer"
)

// TestE2E checks configuration parameters (specified through flags) and then runs
// E2E tests using the Ginkgo runner.
func RunE2ETests(t *testing.T) {
	logs.InitLogs()
	defer logs.FlushLogs()

	gomega.RegisterFailHandler(ginkgo.Fail)
	// Disable skipped tests unless they are explicitly requested.
	if config.GinkgoConfig.FocusString == "" && config.GinkgoConfig.SkipString == "" {
		config.GinkgoConfig.SkipString = `\[Flaky\]|\[Feature:.+\]`
	}

	glog.Infof("Install cert-manager helm chart")
	InstallHelmChart(t)

	glog.Infof("Starting e2e run %q on Ginkgo node %d", framework.RunId, config.GinkgoConfig.ParallelNode)
	if !ginkgo.RunSpecs(t, "cert-manager e2e suite") {
		PrintPodLogs(t)
	}
}

const releaseName = "cm"

func InstallHelmChart(t *testing.T) {
	cmd := exec.Command("helm", "install", "./contrib/charts/cert-manager", "--namespace", "cert-manager", "--name", releaseName, "--values", "./test/fixtures/cert-manager-values.yaml", "--wait")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		t.Errorf("Error installing cert-manager: %s", err)
		t.FailNow()
		return
	}
}

func PrintPodLogs(t *testing.T) {
	glog.Infof("Printing cert-manager logs")
	cmd := exec.Command("kubectl", "logs", "--namespace", "cert-manager", "-l", "app=cert-manager", "-l", "release=cm", "-c", "cert-manager")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		t.Errorf("Error printing cert-manager logs: %s", err)
	}
	glog.Infof("Printing ingress-shim logs")
	cmdShim := exec.Command("kubectl", "logs", "--namespace", "cert-manager", "-l", "app=cert-manager", "-l", "release=cm", "-c", "ingress-shim")
	cmdShim.Stdout = os.Stdout
	cmdShim.Stderr = os.Stderr
	err = cmdShim.Run()
	if err != nil {
		t.Errorf("Error printing ingress-shim logs: %s", err)
	}
}
