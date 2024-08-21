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

package acmeorders

import (
	"fmt"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/util/workqueue"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmacmelisters "github.com/cert-manager/cert-manager/pkg/client/listers/acme/v1"
)

func handleGenericIssuerFunc(
	queue workqueue.TypedRateLimitingInterface[types.NamespacedName],
	orderLister cmacmelisters.OrderLister,
) func(interface{}) {
	return func(obj interface{}) {
		iss, ok := obj.(cmapi.GenericIssuer)
		if !ok {
			runtime.HandleError(fmt.Errorf("object does not implement GenericIssuer %#v", obj))
			return
		}

		certs, err := ordersForGenericIssuer(iss, orderLister)
		if err != nil {
			runtime.HandleError(fmt.Errorf("error looking up Orders observing Issuer/ClusterIssuer: %s/%s", iss.GetObjectMeta().Namespace, iss.GetObjectMeta().Name))
			return
		}
		for _, crt := range certs {
			queue.Add(types.NamespacedName{
				Namespace: crt.Namespace,
				Name:      crt.Name,
			})
		}
	}
}

func ordersForGenericIssuer(iss cmapi.GenericIssuer, orderLister cmacmelisters.OrderLister) ([]*cmacme.Order, error) {
	orders, err := orderLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing certificates: %s", err.Error())
	}

	_, isClusterIssuer := iss.(*cmapi.ClusterIssuer)

	var affected []*cmacme.Order
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
