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

package istio

import (
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/internal/istio"
)

func IsInstalled(ctx *controller.Context) (bool, error) {
	groups, err := ctx.Client.Discovery().ServerGroups()
	if err != nil {
		return false, err
	}

	for _, group := range groups.Groups {
		if group.Name == istio.VirtualServiceGvr().Group {
			return true, nil
		}
	}
	return false, nil
}

func CanListVirtualService(ctx *controller.Context, namespace string) (bool, error) {
	// Check if sa has permissions to list virtualservice
	_, err := ctx.DynamicClient.Resource(istio.VirtualServiceGvr()).Namespace(namespace).List(ctx.RootContext, metav1.ListOptions{})
	if errors.IsForbidden(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}
