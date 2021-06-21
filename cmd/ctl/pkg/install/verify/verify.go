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

package verify

import (
	"context"
	"fmt"
	"log"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
)

type VerifyResult struct {
	Success bool

	DeploymentsSuccess bool
	CertificateSuccess bool

	DeploymentsResult []DeploymentResult
	CertificateError  error
}

type CertificateResult struct {
	Success bool
	Error   error
}

type Options struct {
	Namespace   string
	Deployments []*resource.Info

	genericclioptions.IOStreams
}

func Verify(ctx context.Context, config *rest.Config, options *Options) (*VerifyResult, error) {
	log.SetFlags(0)
	log.SetOutput(options.Out)

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to get kubernetes client: %v", err)
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to get kubernetes client: %v", err)
	}

	deployments := DeploymentDefinitionFromInfo(options.Deployments)
	deploymentResult := DeploymentsReady(ctx, kubeClient, deployments)

	result := &VerifyResult{
		Success:           false,
		DeploymentsResult: deploymentResult,
	}

	if !allReady(deploymentResult) {
		return result, nil
	}
	result.DeploymentsSuccess = true

	ver := version(deploymentResult)
	log.Printf("Detected cert-manager version: \"%s\"", ver)

	err = WaitForTestCertificate(ctx, dynamicClient, ver)
	if err != nil {
		result.CertificateError = err
	} else {
		result.CertificateSuccess = true
		result.Success = true
	}

	return result, nil
}

func version(result []DeploymentResult) string {
	for _, r := range result {
		if r.Version != "" {
			return r.Version
		}
	}
	return ""
}

func allReady(result []DeploymentResult) bool {
	for _, r := range result {
		if r.Status == NotReady || (r.Status == NotFound && r.Deployment.Required) {
			return false
		}
	}
	return true
}
