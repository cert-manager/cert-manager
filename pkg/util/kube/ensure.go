/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package kube

import (
	batch "k8s.io/api/batch/v1"
	api "k8s.io/api/core/v1"
	core "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
)

func EnsureSecret(cl kubernetes.Interface, secret *api.Secret) (*api.Secret, error) {
	s, err := cl.CoreV1().Secrets(secret.Namespace).Create(secret)
	if err != nil {
		if k8sErrors.IsAlreadyExists(err) {
			return cl.CoreV1().Secrets(secret.Namespace).Update(secret)
		}
		return nil, err
	}
	return s, nil
}

func EnsureIngress(cl kubernetes.Interface, ingress *extensions.Ingress) (*extensions.Ingress, error) {
	s, err := cl.ExtensionsV1beta1().Ingresses(ingress.Namespace).Update(ingress)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			return cl.ExtensionsV1beta1().Ingresses(ingress.Namespace).Create(ingress)
		}
		return nil, err
	}
	return s, nil
}

func EnsureService(cl kubernetes.Interface, service *core.Service) (*core.Service, error) {
	s, err := cl.CoreV1().Services(service.Namespace).Update(service)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			return cl.CoreV1().Services(service.Namespace).Create(service)
		}
		return nil, err
	}
	return s, nil
}

func EnsureJob(cl kubernetes.Interface, job *batch.Job) (*batch.Job, error) {
	s, err := cl.BatchV1().Jobs(job.Namespace).Update(job)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			return cl.BatchV1().Jobs(job.Namespace).Create(job)
		}
		return nil, err
	}
	return s, nil
}
