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

package chart

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon/base"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon/internal"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/config"
)

// Chart is a generic Helm chart addon for the test environment
type Chart struct {
	Base *base.Base

	config *config.Config

	// temporary directory used as the --home flag to Helm
	home string

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

	// repository source of this Chart
	Repo Repo
}

var _ internal.Addon = &Chart{}

type Repo struct {
	// name of the repository
	Name string

	// source URL of the repository
	Url string
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

func (c *Chart) Setup(cfg *config.Config, _ ...internal.AddonTransferableData) (internal.AddonTransferableData, error) {
	var err error

	c.config = cfg
	if c.config.Addons.Helm.Path == "" {
		return nil, fmt.Errorf("--helm-binary-path must be set")
	}

	c.home, err = os.MkdirTemp("", "helm-chart-install")
	if err != nil {
		return nil, err
	}

	return nil, nil
}

// Provision an instance of tiller-deploy
func (c *Chart) Provision(ctx context.Context) error {
	if len(c.Repo.Name) > 0 && len(c.Repo.Url) > 0 {
		err := c.addRepo(ctx)
		if err != nil {
			return fmt.Errorf("error adding helm repo: %v", err)
		}
	}

	if c.UpdateDeps {
		err := c.runDepUpdate(ctx)
		if err != nil {
			return fmt.Errorf("error updating helm chart dependencies: %v", err)
		}
	}

	err := c.runInstall(ctx)
	if err != nil {
		return fmt.Errorf("error install helm chart: %v", err)
	}

	return nil
}

func (c *Chart) runDepUpdate(ctx context.Context) error {
	err := c.buildHelmCmd(ctx, "dep", "update", c.ChartName).Run()
	if err != nil {
		return err
	}
	return nil
}

func (c *Chart) runInstall(ctx context.Context) error {
	args := []string{"upgrade", c.ReleaseName, c.ChartName,
		"--install",
		"--wait",
		"--namespace", c.Namespace,
		"--create-namespace",
		"--version", c.ChartVersion}

	for _, v := range c.Values {
		args = append(args, "--values", v)
	}

	for _, s := range c.Vars {
		args = append(args, "--set", fmt.Sprintf("%s=%s", s.Key, s.Value))
	}

	cmd := c.buildHelmCmd(ctx, args...)

	return cmd.Run()
}

func (c *Chart) buildHelmCmd(ctx context.Context, args ...string) *exec.Cmd {
	args = append([]string{
		"--kubeconfig", c.config.KubeConfig,
		"--kube-context", c.config.KubeContext,
	}, args...)
	cmd := exec.CommandContext(ctx, c.config.Addons.Helm.Path, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

// Deprovision the deployed chart
func (c *Chart) Deprovision(ctx context.Context) error {
	cmd := c.buildHelmCmd(ctx, "delete", "--namespace", c.Namespace, c.ReleaseName)
	stdoutBuf := &bytes.Buffer{}
	cmd.Stdout = stdoutBuf

	err := cmd.Run()
	if err != nil {
		_, err2 := io.Copy(os.Stdout, stdoutBuf)
		if err2 != nil {
			return fmt.Errorf("cmd.Run: %v: io.Copy: %v", err, err2)
		}

		// Ignore deprovisioning errors
		// TODO: only ignore "failed to delete because it doesn't exist" errors
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
	return c.ReleaseName != ""
}

func (c *Chart) Logs(ctx context.Context) (map[string]string, error) {
	kc := c.Base.Details().KubeClient
	oldLabelPods, err := kc.CoreV1().Pods(c.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "release=" + c.ReleaseName})
	if err != nil {
		return nil, err
	}

	// also check pods with the new style labels used in the cert-manager chart
	newLabelPods, err := kc.CoreV1().Pods(c.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/instance=" + c.ReleaseName})
	if err != nil {
		return nil, err
	}
	podList := append([]corev1.Pod(nil), oldLabelPods.Items...)
	podList = append(podList, newLabelPods.Items...)

	out := make(map[string]string)
	for _, pod := range podList {
		for _, con := range pod.Spec.Containers {
			for _, b := range []bool{true, false} {
				resp := kc.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
					Container: con.Name,
					Previous:  b,
				}).Do(ctx)

				err := resp.Error()
				if err != nil {
					continue
				}

				logs, err := resp.Raw()
				if err != nil {
					continue
				}

				outPath := path.Join(c.Namespace,
					fmt.Sprintf("%s-%s", pod.Name, con.Name))

				if b {
					outPath = fmt.Sprintf("%s-previous", outPath)
				}

				out[outPath] = string(logs)
			}
		}
	}

	return out, nil
}

func (c *Chart) addRepo(ctx context.Context) error {
	err := c.buildHelmCmd(ctx, "repo", "add", c.Repo.Name, c.Repo.Url).Run()
	if err != nil {
		return err
	}
	return nil
}
