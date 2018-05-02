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
	"io"
	"os"
	"os/exec"
	"path"
	"testing"

	"github.com/golang/glog"
	"github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/config"
	"github.com/onsi/ginkgo/reporters"
	"github.com/onsi/gomega"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/jetstack/cert-manager/pkg/logs"
	_ "github.com/jetstack/cert-manager/test/e2e/certificate"
	_ "github.com/jetstack/cert-manager/test/e2e/clusterissuer"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	_ "github.com/jetstack/cert-manager/test/e2e/ingress"
	_ "github.com/jetstack/cert-manager/test/e2e/issuer"
)

const certManagerDeploymentNamespace = "cert-manager"

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

	glog.Infof("Installing cert-manager helm chart")
	InstallHelmChart(t, releaseName, "./contrib/charts/cert-manager", certManagerDeploymentNamespace, "./test/fixtures/cert-manager-values.yaml")

	glog.Infof("Installing pebble chart")
	// 10 minute timeout for pebble install due to large images
	extraArgs := []string{"--timeout", "600"}
	if framework.TestContext.PebbleImageRepo != "" {
		extraArgs = append(extraArgs, "--set", "image.repository="+framework.TestContext.PebbleImageRepo)
	}
	if framework.TestContext.PebbleImageTag != "" {
		extraArgs = append(extraArgs, "--set", "image.tag="+framework.TestContext.PebbleImageTag)
	}
	InstallHelmChart(t, "pebble", "./contrib/charts/pebble", "pebble", "./test/fixtures/pebble-values.yaml", extraArgs...)

	InstallHelmChart(t, "vault", "./contrib/charts/vault", "vault", "./test/fixtures/vault-values.yaml")

	glog.Infof("Starting e2e run %q on Ginkgo node %d", framework.RunId, config.GinkgoConfig.ParallelNode)

	var r []ginkgo.Reporter
	if framework.TestContext.ReportDir != "" {
		r = append(r, reporters.NewJUnitReporter(path.Join(framework.TestContext.ReportDir, "junit_00.xml")))
	}
	if !ginkgo.RunSpecsWithDefaultAndCustomReporters(t, "cert-manager e2e suite", r) {
		PrintPodLogs(t)
	}
}

const releaseName = "cm"

func InstallHelmChart(t *testing.T, releaseName, chartName, namespace, values string, extraArgs ...string) {
	args := []string{"install", chartName, "--namespace", namespace, "--name", releaseName, "--values", values, "--wait"}
	args = append(args, extraArgs...)
	cmd := exec.Command("helm", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		t.Errorf("Error installing %q: %s", releaseName, err)
		t.FailNow()
		return
	}
}

func ArtifactWriteCloser(name string) (io.WriteCloser, error) {
	f, err := os.OpenFile(path.Join(framework.TestContext.ReportDir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func PrintPodLogs(t *testing.T) {
	glog.Infof("Printing cert-manager logs")
	cmOut, err := ArtifactWriteCloser("cert-manager-logs.txt")
	if err != nil {
		t.Errorf("Error saving cert-manager logs")
		t.FailNow()
		return
	}
	defer cmOut.Close()
	cmd := exec.Command("kubectl", "logs", "--namespace", "cert-manager", "-l", "app=cert-manager", "-l", "release=cm", "-c", "cert-manager", "--tail", "10000")
	cmd.Stdout = cmOut
	cmd.Stderr = cmOut
	err = cmd.Run()
	if err != nil {
		t.Errorf("Error getting cert-manager logs: %v", err)
		t.FailNow()
		return
	}
}
