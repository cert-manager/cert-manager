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

package chart

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
	"github.com/jetstack/cert-manager/test/e2e/framework/log"
)

// Chart is a generic Helm chart addon for the test environment
type Chart struct {
	config        *config.Config
	tillerDetails *tiller.Details
	// temporary directory used as the --home flag to Helm
	home string

	// Tiller is the tiller instance to submit the release to
	Tiller *tiller.Tiller

	// ReleaseName for this Helm release
	// `helm install --name {{ReleaseName}}`
	ReleaseName string

	// Namespace for the Helm release
	// `helm install --namespace {{Namespace}}`
	Namespace string

	// ChartName is the name of the chart to deploy
	// `helm install {{ChartName}}``
	ChartName string

	// ChartVersion is the version of the chart to deploy
	// `helm install --version {{ChartVersion}}`
	ChartVersion string

	// Vars are additional --set arguments for helm install
	// `helm install --set {{Vars[0].Key}}={{Vars[0].Value}} --set {{Vars[1].Key}}={{Vars[1].Value}} ...`
	Vars []StringTuple

	// Values is a list of paths to additional values.yaml files to include
	// `helm install --values {{Values[0]}} --values {{Values[1]}} ...`
	Values []string

	// If UpdateDeps is true, 'helm dep update' will be run against the chart
	// before installing.
	// This should only be set to true when the ChartName is a local path on disk.
	UpdateDeps bool
}

// StringTuple is a tuple of strings, used to create ordered maps
type StringTuple struct {
	Key   string
	Value string
}

// Details return the details about the Tiller instance deployed
type Details struct {
	// Helm chart release name
	ReleaseName string

	// Namespace that Tiller has been deployed into
	Namespace string
}

func (c *Chart) Setup(cfg *config.Config) error {
	var err error

	c.config = cfg
	if c.config.Addons.Helm.Path == "" {
		return fmt.Errorf("--helm-binary-path must be set")
	}
	if c.Tiller == nil {
		return fmt.Errorf("tiller base addon must be provided")
	}
	c.tillerDetails, err = c.Tiller.Details()
	if err != nil {
		return err
	}

	c.home, err = ioutil.TempDir("", "helm-chart-install")
	if err != nil {
		return err
	}

	return nil
}

// Provision an instance of tiller-deploy
func (c *Chart) Provision() error {
	err := c.runHelmClientInit()
	if err != nil {
		return fmt.Errorf("error running 'helm init': %v", err)
	}

	if c.UpdateDeps {
		err := c.runDepUpdate()
		if err != nil {
			return fmt.Errorf("error updating helm chart dependencies: %v", err)
		}
	}

	err = c.runInstall()
	if err != nil {
		return fmt.Errorf("error install helm chart: %v", err)
	}

	err = c.Tiller.Base.Details().Helper().WaitForAllPodsRunningInNamespace(c.Namespace)
	if err != nil {
		return err
	}

	return nil
}

func (c *Chart) runHelmClientInit() error {
	err := c.buildHelmCmd("init", "--client-only").Run()
	if err != nil {
		return err
	}
	return nil
}

func (c *Chart) runDepUpdate() error {
	err := c.buildHelmCmd("dep", "update", c.ChartName).Run()
	if err != nil {
		return err
	}
	return nil
}

func (c *Chart) runInstall() error {
	args := []string{"install", c.ChartName,
		"--wait",
		"--namespace", c.Namespace,
		"--name", c.ReleaseName}

	for _, v := range c.Values {
		args = append(args, "--values", v)
	}

	for _, s := range c.Vars {
		args = append(args, "--set", fmt.Sprintf("%s=%s", s.Key, s.Value))
	}

	cmd := c.buildHelmCmd(args...)
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func (c *Chart) buildHelmCmd(args ...string) *exec.Cmd {
	args = append([]string{
		"--home", c.home,
		"--kubeconfig", c.tillerDetails.KubeConfig,
		"--kube-context", c.tillerDetails.KubeContext,
		"--tiller-namespace", c.tillerDetails.Namespace,
	}, args...)
	cmd := exec.Command(c.config.Addons.Helm.Path, args...)
	cmd.Stdout = log.Writer
	cmd.Stderr = log.Writer
	return cmd
}

func (c *Chart) getHelmVersion() (string, error) {
	cmd := c.buildHelmCmd("version", "--template", "{{.Client.Version}}")
	cmd.Stdout = nil
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	defer out.Close()

	err = cmd.Run()
	if err != nil {
		return "", err
	}

	outBytes, err := ioutil.ReadAll(out)
	if err != nil {
		return "", err
	}

	return string(outBytes), nil
}

// Deprovision the deployed instance of tiller-deploy
func (c *Chart) Deprovision() error {
	err := c.buildHelmCmd("delete", "--purge", c.ReleaseName).Run()
	if err != nil {
		// Ignore deprovisioning errors
		// TODO: only ignore failed to delete because it doesn't exist errors
		return nil
	}

	// attempt to cleanup
	os.RemoveAll(c.home)

	// TODO: delete namespace manually too
	return nil
}

// Details must be possible to compute without Provision being called if we want
// to be able to provision global/shared instances of Tiller.
func (c *Chart) Details() (*Details, error) {
	d := &Details{
		ReleaseName: c.ReleaseName,
		Namespace:   c.Namespace,
	}

	return d, nil
}

func (c *Chart) SupportsGlobal() bool {
	// We can't run in global mode if the release name is not set, as there's
	// no way for us to communicate the generated release name to other test
	// runners when running in parallel mode.
	if c.ReleaseName == "" {
		return false
	}

	return true
}

func (c *Chart) Logs() (map[string]string, error) {
	kc := c.Tiller.Base.Details().KubeClient
	pods, err := kc.CoreV1().Pods(c.Namespace).List(metav1.ListOptions{LabelSelector: "release=" + c.ReleaseName})
	if err != nil {
		return nil, err
	}

	out := make(map[string]string)
	for _, pod := range pods.Items {
		// Only grab logs from the first container in the pod
		// TODO: grab logs from all containers
		containerName := pod.Spec.Containers[0].Name
		resp := kc.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
			Container: containerName,
		}).Do()

		err := resp.Error()
		if err != nil {
			continue
		}

		logs, err := resp.Raw()
		if err != nil {
			continue
		}

		outPath := path.Join(c.Namespace, pod.Name)
		out[outPath] = string(logs)
	}

	return out, nil
}
