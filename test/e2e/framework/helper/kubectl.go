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

package helper

import (
	"context"
	"os/exec"
	"strings"

	"github.com/cert-manager/cert-manager/e2e-tests/framework/log"
)

type Kubectl struct {
	namespace   string
	kubectl     string
	kubeconfig  string
	kubecontext string
}

func (k *Kubectl) Describe(ctx context.Context, resources ...string) error {
	resourceNames := strings.Join(resources, ",")
	return k.Run(ctx, "describe", resourceNames)
}

func (k *Kubectl) DescribeResource(ctx context.Context, resource, name string) error {
	return k.Run(ctx, "describe", resource, name)
}

func (h *Helper) Kubectl(ns string) *Kubectl {
	return &Kubectl{
		namespace:   ns,
		kubectl:     h.cfg.Kubectl,
		kubeconfig:  h.cfg.KubeConfig,
		kubecontext: h.cfg.KubeContext,
	}
}

func (k *Kubectl) Run(ctx context.Context, args ...string) error {
	baseArgs := []string{"--kubeconfig", k.kubeconfig, "--context", k.kubecontext}
	if k.namespace == "" {
		baseArgs = append(baseArgs, "--all-namespaces")
	} else {
		baseArgs = []string{"--namespace", k.namespace}
	}
	args = append(baseArgs, args...)
	cmd := exec.CommandContext(ctx, k.kubectl, args...)
	cmd.Stdout = log.Writer
	cmd.Stderr = log.Writer
	return cmd.Run()
}
