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
)

type objectLister interface {
	List(selector labels.Selector) (ret []runtime.Object, err error)
	Objects(namespace string) objectNamespaceLister
}

type objectNamespaceLister interface {
	List(selector labels.Selector) (ret []runtime.Object, err error)
	Get(name string) (runtime.Object, error)
}

type internalIngressLister struct {
	l networkinglisters.IngressLister
}

type internalIngressNamespaceLister struct {
	l networkinglisters.IngressNamespaceLister
}

func (i *internalIngressLister) List(selector labels.Selector) (ret []runtime.Object, err error) {
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

func (i *internalIngressLister) Objects(namespace string) objectNamespaceLister {
	return &internalIngressNamespaceLister{i.l.Ingresses(namespace)}
}

func (i *internalIngressNamespaceLister) List(selector labels.Selector) (ret []runtime.Object, err error) {
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
