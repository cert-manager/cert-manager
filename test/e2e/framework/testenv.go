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

package framework

import (
	"fmt"
	"time"

	"k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// Defines methods that help provision test environments

const (
	// How often to poll for conditions
	Poll = 2 * time.Second
)

// CreateKubeNamespace creates a new Kubernetes Namespace for a test.
func (f *Framework) CreateKubeNamespace(baseName string) (*v1.Namespace, error) {
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("e2e-tests-%v-", baseName),
		},
	}

	return f.KubeClientSet.CoreV1().Namespaces().Create(ns)
}

// CreateKubeResourceQuota provisions a ResourceQuota resource in the target
// namespace.
func (f *Framework) CreateKubeResourceQuota() (*v1.ResourceQuota, error) {
	quota := &v1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-e2e-quota",
			Namespace: f.Namespace.Name,
		},
		Spec: v1.ResourceQuotaSpec{
			Hard: v1.ResourceList{
				"cpu":             resource.MustParse("16"),
				"limits.cpu":      resource.MustParse("16"),
				"requests.cpu":    resource.MustParse("16"),
				"memory":          resource.MustParse("32G"),
				"limits.memory":   resource.MustParse("32G"),
				"requests.memory": resource.MustParse("32G"),
			},
		},
	}
	return f.KubeClientSet.CoreV1().ResourceQuotas(f.Namespace.Name).Create(quota)
}

// DeleteKubeNamespace will delete a namespace resource
func (f *Framework) DeleteKubeNamespace(namespace string) error {
	return f.KubeClientSet.CoreV1().Namespaces().Delete(namespace, nil)
}

// WaitForKubeNamespaceNotExist will wait for the namespace with the given name
// to not exist for up to 2 minutes.
func (f *Framework) WaitForKubeNamespaceNotExist(namespace string) error {
	return wait.PollImmediate(Poll, time.Minute*2, namespaceNotExist(f.KubeClientSet, namespace))
}

func namespaceNotExist(c kubernetes.Interface, namespace string) wait.ConditionFunc {
	return func() (bool, error) {
		_, err := c.CoreV1().Namespaces().Get(namespace, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return false, nil
	}
}
