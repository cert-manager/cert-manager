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

package controller

import (
	"fmt"

	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func (c *controller) ingressesForCertificate(crt *v1.Certificate) ([]*networkingv1beta1.Ingress, error) {
	ings, err := c.ingressLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing certificates: %s", err.Error())
	}

	var affected []*networkingv1beta1.Ingress
	for _, ing := range ings {
		if crt.Namespace != ing.Namespace {
			continue
		}

		if metav1.IsControlledBy(crt, ing) {
			affected = append(affected, ing)
		}
	}

	return affected, nil
}
