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

package certificates

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	extv1beta1 "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func (c *Controller) certificatesForSecret(secret *corev1.Secret) ([]*v1alpha1.Certificate, error) {
	crts, err := c.certificateLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing certificiates: %s", err.Error())
	}

	var affected []*v1alpha1.Certificate
	for _, crt := range crts {
		if crt.Namespace != secret.Namespace {
			continue
		}
		if crt.Spec.SecretName == secret.Name {
			affected = append(affected, crt)
		}
	}

	return affected, nil
}

func (c *Controller) certificatesForIngress(ing *extv1beta1.Ingress) ([]*v1alpha1.Certificate, error) {
	crts, err := c.certificateLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing certificiates: %s", err.Error())
	}

	var affected []*v1alpha1.Certificate
	for _, crt := range crts {
		if crt.Namespace != ing.Namespace {
			continue
		}
		if crt.Spec.ACME != nil {
			for _, cfg := range crt.Spec.ACME.Config {
				if cfg.HTTP01 == nil {
					continue
				}
				if cfg.HTTP01.Ingress == ing.Name {
					affected = append(affected, crt)
					continue
				}
			}
		}
	}

	return affected, nil
}
