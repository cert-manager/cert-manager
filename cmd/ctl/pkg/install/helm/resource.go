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

package helm

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"

	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/kube"
	"k8s.io/cli-runtime/pkg/resource"
)

const (
	customResourceDefinitionGroup    = "apiextensions.k8s.io"
	customResourceDefinitionKind     = "CustomResourceDefinition"
	customResourceDefinitionResource = "customresourcedefinition"

	deploymentGroup    = "apps"
	deploymentKind     = "Deployment"
	deploymentResource = "deployment"
)

func GetChartResourceInfo(ch *chart.Chart, manifest string, includeCrdFolder bool, kubeClient kube.Interface) ([]*resource.Info, error) {
	resources := make([]*resource.Info, 0)

	if includeCrdFolder {
		for _, obj := range ch.CRDObjects() {
			res, err := kubeClient.Build(bytes.NewBuffer(obj.File.Data), false)
			if err != nil {
				fmt.Printf("failed to parse CRDs from %s: %s", obj.Name, err)
				return nil, errors.New(fmt.Sprintf("failed to parse CRDs from %s: %s", obj.Name, err))
			}
			resources = append(resources, res...)
		}
	}

	res, err := kubeClient.Build(bytes.NewBufferString(manifest), false)
	if err != nil {
		fmt.Printf("failed to parse CRDs from render: %s", err)
		return nil, errors.New(fmt.Sprintf("failed to parse CRDs from render: %s", err))
	}
	resources = append(resources, res...)

	return resources, nil
}

func FilterResources(resources []*resource.Info, filter func(string, string) bool) ([]*resource.Info, error) {
	crds := make([]*resource.Info, 0)
	for _, res := range resources {
		groupVersionKind := res.Object.GetObjectKind().GroupVersionKind()
		if filter(groupVersionKind.Group, groupVersionKind.Kind) {
			crds = append(crds, res)
		}
	}

	return crds, nil
}

func FetchResources(resources []*resource.Info, kubeClient kube.Interface) ([]*resource.Info, error) {
	detected := make([]*resource.Info, 0)

	for _, info := range resources {
		helper := resource.NewHelper(info.Client, info.Mapping)
		if obj, err := helper.Get(info.Namespace, info.Name); err == nil && obj != nil {
			info.Object = obj

			detected = append(detected, info)
		}
	}

	return detected, nil
}

func FilterCrdResources(resources []*resource.Info) ([]*resource.Info, error) {
	return FilterResources(resources, func(group string, kind string) bool {
		return (group == customResourceDefinitionGroup) && (kind == customResourceDefinitionKind)
	})
}

func FilterDeploymentResources(resources []*resource.Info) ([]*resource.Info, error) {
	return FilterResources(resources, func(group string, kind string) bool {
		return (group == deploymentGroup) && (kind == deploymentKind)
	})
}
