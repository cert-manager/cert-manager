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

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/cli-runtime/pkg/resource"

	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/kube"
)

const (
	customResourceDefinitionGroup = "apiextensions.k8s.io"
	customResourceDefinitionKind  = "CustomResourceDefinition"
)

// Build a list of resource.Info objects from a chart definition and its rendered manifest.
// The chart is only used for its CRDObjects() function that returns a list of all files in the /crds folder.
// The includeCrdFolder option is used to not include the /crds folder. Current versions of the cert-manager chart
// don't have a crds folder, so this option is only in case this would ever change. The manifest includes
// all types of resources (not only crds).
func GetChartResourceInfo(ch *chart.Chart, manifest string, includeCrdFolder bool, kubeClient kube.Interface) ([]*resource.Info, error) {
	resources := make([]*resource.Info, 0)

	if includeCrdFolder {
		for _, obj := range ch.CRDObjects() {
			res, err := kubeClient.Build(bytes.NewBuffer(obj.File.Data), false)
			if err != nil {
				return nil, fmt.Errorf("failed to parse CRDs from %s: %s", obj.Name, err)
			}
			resources = append(resources, res...)
		}
	}

	res, err := kubeClient.Build(bytes.NewBufferString(manifest), false)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRDs from render: %s", err)
	}
	resources = append(resources, res...)

	return resources, nil
}

func filterResources(resources []*resource.Info, filter func(*resource.Info) bool) []*resource.Info {
	crds := make([]*resource.Info, 0)
	for _, res := range resources {
		if filter(res) {
			crds = append(crds, res)
		}
	}

	return crds
}

// Retrieve the latest version of the resources from the kubernetes cluster.
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

// Filter resources that are Custom Resource Definitions.
func FilterCrdResources(resources []*resource.Info) []*resource.Info {
	return filterResources(resources, func(res *resource.Info) bool {
		groupVersionKind := res.Object.GetObjectKind().GroupVersionKind()
		return (groupVersionKind.Group == customResourceDefinitionGroup) && (groupVersionKind.Kind == customResourceDefinitionKind)
	})
}

// Filter resources that are scoped to a namespace and that live in the provided namespace.
func FilterNamespacedResources(resources []*resource.Info, namespace string) []*resource.Info {
	return filterResources(resources, func(res *resource.Info) bool {
		return (res.Mapping.Scope.Name() == meta.RESTScopeNameNamespace) && (res.Namespace == namespace)
	})
}
