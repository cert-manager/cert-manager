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

package listers

import (
	"k8s.io/apimachinery/pkg/labels"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
)

var _ cmlisters.OrderLister = &FakeOrderLister{}
var _ cmlisters.OrderNamespaceLister = &FakeOrderNamespaceLister{}

type FakeOrderLister struct {
	ListFn   func(selector labels.Selector) (ret []*v1alpha1.Order, err error)
	OrdersFn func(namespace string) cmlisters.OrderNamespaceLister
}

type FakeOrderNamespaceLister struct {
	ListFn func(selector labels.Selector) (ret []*v1alpha1.Order, err error)
	GetFn  func(name string) (ret *v1alpha1.Order, err error)
}

func NewFakeOrderLister() *FakeOrderLister {
	return &FakeOrderLister{
		ListFn: func(selector labels.Selector) (ret []*v1alpha1.Order, err error) {
			return nil, nil
		},

		OrdersFn: func(namespace string) cmlisters.OrderNamespaceLister {
			return nil
		},
	}
}

func NewFakeOrderNamespaceLister() *FakeOrderNamespaceLister {
	return &FakeOrderNamespaceLister{
		ListFn: func(selector labels.Selector) (ret []*v1alpha1.Order, err error) {
			return nil, nil
		},
		GetFn: func(name string) (ret *v1alpha1.Order, err error) {
			return nil, nil
		},
	}
}

func (f *FakeOrderLister) List(selector labels.Selector) (ret []*v1alpha1.Order, err error) {
	return f.ListFn(selector)
}

func (f *FakeOrderLister) Orders(namespace string) cmlisters.OrderNamespaceLister {
	return f.OrdersFn(namespace)
}

func (f *FakeOrderNamespaceLister) List(selector labels.Selector) (ret []*v1alpha1.Order, err error) {
	return f.ListFn(selector)
}

func (f *FakeOrderNamespaceLister) Get(name string) (*v1alpha1.Order, error) {
	return f.GetFn(name)
}
