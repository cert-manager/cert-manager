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

package helper

import (
	"os/exec"
	"strings"

	"github.com/jetstack/cert-manager/test/e2e/framework/log"
)

type Kubectl struct {
	namespace   string
	kubectl     string
	kubeconfig  string
	kubecontext string
}

func (k *Kubectl) Describe(resources ...string) error {
	resourceNames := strings.Join(resources, ",")
	return k.Run("describe", resourceNames)
}

func (k *Kubectl) DescribeResource(resource, name string) error {
	return k.Run("describe", resource, name)
}

func (h *Helper) Kubectl(ns string) *Kubectl {
	return &Kubectl{
		namespace:   ns,
		kubectl:     h.cfg.Kubectl,
		kubeconfig:  h.cfg.KubeConfig,
		kubecontext: h.cfg.KubeContext,
	}
}

func (k *Kubectl) Run(args ...string) error {
	baseArgs := []string{"--kubeconfig", k.kubeconfig, "--context", k.kubecontext}
	if k.namespace == "" {
		baseArgs = append(baseArgs, "--all-namespaces")
	} else {
		baseArgs = []string{"--namespace", k.namespace}
	}
	args = append(baseArgs, args...)
	cmd := exec.Command(k.kubectl, args...)
	cmd.Stdout = log.Writer
	cmd.Stderr = log.Writer
	return cmd.Run()
}
