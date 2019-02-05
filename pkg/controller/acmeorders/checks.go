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

package acmeorders

import (
	"fmt"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/runtime"
)

func (c *Controller) handleGenericIssuer(obj interface{}) {
	iss, ok := obj.(cmapi.GenericIssuer)
	if !ok {
		runtime.HandleError(fmt.Errorf("Object does not implement GenericIssuer %#v", obj))
		return
	}

	certs, err := c.ordersForGenericIssuer(iss)
	if err != nil {
		runtime.HandleError(fmt.Errorf("Error looking up Orders observing Issuer/ClusterIssuer: %s/%s", iss.GetObjectMeta().Namespace, iss.GetObjectMeta().Name))
		return
	}
	for _, crt := range certs {
		key, err := keyFunc(crt)
		if err != nil {
			runtime.HandleError(err)
			continue
		}
		c.queue.Add(key)
	}
}

func (c *Controller) ordersForGenericIssuer(iss cmapi.GenericIssuer) ([]*cmapi.Order, error) {
	orders, err := c.orderLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing certificiates: %s", err.Error())
	}

	_, isClusterIssuer := iss.(*cmapi.ClusterIssuer)

	var affected []*cmapi.Order
	for _, o := range orders {
		if isClusterIssuer && o.Spec.IssuerRef.Kind != cmapi.ClusterIssuerKind {
			continue
		}
		if !isClusterIssuer {
			if o.Namespace != iss.GetObjectMeta().Namespace {
				continue
			}
		}
		if o.Spec.IssuerRef.Name != iss.GetObjectMeta().Name {
			continue
		}
		affected = append(affected, o)
	}

	return affected, nil
}
