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

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha2"
	acmelisters "github.com/jetstack/cert-manager/pkg/client/listers/acme/v1alpha2"
)

var _ acmelisters.OrderLister = &FakeOrderLister{}
var _ acmelisters.OrderNamespaceLister = &FakeOrderNamespaceLister{}

type FakeOrderLister struct {
	ListFn   func(selector labels.Selector) (ret []*cmacme.Order, err error)
	OrdersFn func(namespace string) acmelisters.OrderNamespaceLister
}

type FakeOrderNamespaceLister struct {
	ListFn func(selector labels.Selector) (ret []*cmacme.Order, err error)
	GetFn  func(name string) (ret *cmacme.Order, err error)
}

func NewFakeOrderLister() *FakeOrderLister {
	return &FakeOrderLister{
		ListFn: func(selector labels.Selector) (ret []*cmacme.Order, err error) {
			return nil, nil
		},

		OrdersFn: func(namespace string) acmelisters.OrderNamespaceLister {
			return nil
		},
	}
}

func NewFakeOrderNamespaceLister() *FakeOrderNamespaceLister {
	return &FakeOrderNamespaceLister{
		ListFn: func(selector labels.Selector) (ret []*cmacme.Order, err error) {
			return nil, nil
		},
		GetFn: func(name string) (ret *cmacme.Order, err error) {
			return nil, nil
		},
	}
}

func (f *FakeOrderLister) List(selector labels.Selector) (ret []*cmacme.Order, err error) {
	return f.ListFn(selector)
}

func (f *FakeOrderLister) Orders(namespace string) acmelisters.OrderNamespaceLister {
	return f.OrdersFn(namespace)
}

func (f *FakeOrderNamespaceLister) List(selector labels.Selector) (ret []*cmacme.Order, err error) {
	return f.ListFn(selector)
}

func (f *FakeOrderNamespaceLister) Get(name string) (*cmacme.Order, error) {
	return f.GetFn(name)
}
