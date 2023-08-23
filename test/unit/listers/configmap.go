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

package listers

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	clientcorev1 "k8s.io/client-go/listers/core/v1"
)

var _ clientcorev1.ConfigMapLister = &FakeConfigMapLister{}
var _ clientcorev1.ConfigMapNamespaceLister = &FakeConfigMapNamespaceLister{}

type FakeConfigMapListerModifier func(*FakeConfigMapLister)
type FakeConfigMapNamespaceListerModifier func(*FakeConfigMapNamespaceLister)

type FakeConfigMapLister struct {
	ListFn       func(selector labels.Selector) (ret []*corev1.ConfigMap, err error)
	ConfigMapsFn func(namespace string) clientcorev1.ConfigMapNamespaceLister
}

type FakeConfigMapNamespaceLister struct {
	ListFn func(selector labels.Selector) (ret []*corev1.ConfigMap, err error)
	GetFn  func(name string) (ret *corev1.ConfigMap, err error)
}

func NewFakeConfigMapLister(mods ...FakeConfigMapListerModifier) *FakeConfigMapLister {
	return FakeConfigMapListerFrom(&FakeConfigMapLister{
		ListFn: func(selector labels.Selector) (ret []*corev1.ConfigMap, err error) {
			return nil, nil
		},

		ConfigMapsFn: func(namespace string) clientcorev1.ConfigMapNamespaceLister {
			return nil
		},
	}, mods...)
}

func NewFakeConfigMapNamespaceLister(mods ...FakeConfigMapNamespaceListerModifier) *FakeConfigMapNamespaceLister {
	return FakeConfigMapNamespaceListerFrom(&FakeConfigMapNamespaceLister{
		ListFn: func(selector labels.Selector) (ret []*corev1.ConfigMap, err error) {
			return nil, nil
		},
		GetFn: func(name string) (ret *corev1.ConfigMap, err error) {
			return nil, nil
		},
	}, mods...)
}

func (f *FakeConfigMapLister) List(selector labels.Selector) (ret []*corev1.ConfigMap, err error) {
	return f.ListFn(selector)
}

func (f *FakeConfigMapLister) ConfigMaps(namespace string) clientcorev1.ConfigMapNamespaceLister {
	return f.ConfigMapsFn(namespace)
}

func (f *FakeConfigMapNamespaceLister) List(selector labels.Selector) (ret []*corev1.ConfigMap, err error) {
	return f.ListFn(selector)
}

func (f *FakeConfigMapNamespaceLister) Get(name string) (*corev1.ConfigMap, error) {
	return f.GetFn(name)
}

func FakeConfigMapNamespaceListerFrom(f *FakeConfigMapNamespaceLister, mods ...FakeConfigMapNamespaceListerModifier) *FakeConfigMapNamespaceLister {
	for _, mod := range mods {
		mod(f)
	}
	return f
}

func (f *FakeConfigMapNamespaceLister) SetFakeConfigMapNamespaceListerGet(ret *corev1.ConfigMap,
	err error) *FakeConfigMapNamespaceLister {
	f.GetFn = func(string) (*corev1.ConfigMap, error) {
		return ret, err
	}

	return f
}

func FakeConfigMapListerFrom(s *FakeConfigMapLister, mods ...FakeConfigMapListerModifier) *FakeConfigMapLister {
	for _, mod := range mods {
		mod(s)
	}
	return s
}

func SetFakeConfigMapListerConfigMap(s func(namespace string) clientcorev1.ConfigMapNamespaceLister) FakeConfigMapListerModifier {
	return func(f *FakeConfigMapLister) {
		f.ConfigMapsFn = s
	}
}

func SetFakeConfigMapNamespaceListerGet(cm *corev1.ConfigMap, err error) FakeConfigMapListerModifier {
	return func(f *FakeConfigMapLister) {
		f.ConfigMapsFn = func(namespace string) clientcorev1.ConfigMapNamespaceLister {
			return &FakeConfigMapNamespaceLister{
				GetFn: func(name string) (*corev1.ConfigMap, error) {
					return cm, err
				},
			}
		}
	}
}
