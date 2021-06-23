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

package controller

import (
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	networkinglisters "k8s.io/client-go/listers/networking/v1beta1"
	"k8s.io/client-go/tools/cache"
	gatewaylisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1alpha1"
)

// objectLister is the most minimal generic lister.
// it is used in certificate-shim as an interface that can list gateways or ingresses
type objectLister interface {
	List(selector labels.Selector) (ret []runtime.Object, err error)
	Objects(namespace string) cache.GenericNamespaceLister
}

// internalIngressLister wraps an IngressLister into an objectLister
type internalIngressLister struct {
	l networkinglisters.IngressLister
}

// internalIngressNamespaceLister wraps an IngressNamespaceLister into a cache.GenericNamespaceLister
type internalIngressNamespaceLister struct {
	l networkinglisters.IngressNamespaceLister
}

func (i *internalIngressLister) List(selector labels.Selector) ([]runtime.Object, error) {
	ingresses, err := i.l.List(selector)
	if err != nil {
		return nil, err
	}
	var objs []runtime.Object

	for _, i := range ingresses {
		objs = append(objs, i)
	}

	return objs, nil
}

func (i *internalIngressLister) Objects(namespace string) cache.GenericNamespaceLister {
	return &internalIngressNamespaceLister{i.l.Ingresses(namespace)}
}

func (i *internalIngressNamespaceLister) List(selector labels.Selector) ([]runtime.Object, error) {
	ingresses, err := i.l.List(selector)
	if err != nil {
		return nil, err
	}
	var objs []runtime.Object

	for _, i := range ingresses {
		objs = append(objs, i)
	}

	return objs, nil
}

func (i *internalIngressNamespaceLister) Get(name string) (runtime.Object, error) {
	return i.l.Get(name)
}

// internalGatewayLister wraps a GatewayLister into an objectLister
type internalGatewayLister struct {
	gl gatewaylisters.GatewayLister
}

func (i *internalGatewayLister) List(selector labels.Selector) ([]runtime.Object, error) {
	gateways, err := i.gl.List(selector)
	if err != nil {
		return nil, err
	}
	var objects []runtime.Object
	for _, g := range gateways {
		objects = append(objects, g)
	}
	return objects, nil
}

func (i *internalGatewayLister) Objects(namespace string) cache.GenericNamespaceLister {
	return &internalGatewayNamespaceLister{gl: i.gl.Gateways(namespace)}
}

// internalGatewayNamespaceLister wraps a GatewayNamespaceLister into a cache.GenericNamespaceLister
type internalGatewayNamespaceLister struct {
	gl gatewaylisters.GatewayNamespaceLister
}

func (i *internalGatewayNamespaceLister) List(selector labels.Selector) ([]runtime.Object, error) {
	gateways, err := i.gl.List(selector)
	if err != nil {
		return nil, err
	}
	var objects []runtime.Object
	for _, g := range gateways {
		objects = append(objects, g)
	}
	return objects, nil
}

func (i *internalGatewayNamespaceLister) Get(name string) (runtime.Object, error) {
	return i.gl.Get(name)
}
