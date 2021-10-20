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

	"helm.sh/helm/v3/pkg/kube"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/cli-runtime/pkg/resource"
)

const (
	customResourceDefinitionGroup = "apiextensions.k8s.io"
	customResourceDefinitionKind  = "CustomResourceDefinition"
)

// Build a list of resource.Info objects from a rendered manifest.
func ParseMultiDocumentYAML(manifest string, kubeClient kube.Interface) ([]*resource.Info, error) {
	resources := make([]*resource.Info, 0)

	res, err := kubeClient.Build(bytes.NewBufferString(manifest), false)
	if err != nil {
		return nil, fmt.Errorf("Parsing the CRDs from the rendered manifest was not successful: %w", err)
	}
	resources = append(resources, res...)

	return resources, nil
}

func filterResources(resources []*resource.Info, filter func(*resource.Info) bool) []*resource.Info {
	filtered := make([]*resource.Info, 0)
	for _, res := range resources {
		if filter(res) {
			filtered = append(filtered, res)
		}
	}

	return filtered
}

// Retrieve the latest version of the resources from the kubernetes cluster.
func FetchResources(resources []*resource.Info, kubeClient kube.Interface) ([]*resource.Info, error) {
	detected := make([]*resource.Info, 0)

	for _, info := range resources {
		helper := resource.NewHelper(info.Client, info.Mapping)
		obj, err := helper.Get(info.Namespace, info.Name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}

			return nil, err
		}

		info.Object = obj
		detected = append(detected, info)
	}

	return detected, nil
}

// Filter resources that are Custom Resource Definitions.
func FilterCrdResources(resources []*resource.Info) []*resource.Info {
	return filterResources(resources, func(res *resource.Info) bool {
		groupVersionKind := res.Object.GetObjectKind().GroupVersionKind()
		return (groupVersionKind.Group == customResourceDefinitionGroup) && (groupVersionKind.Kind == customResourceDefinitionKind)
	})
}
