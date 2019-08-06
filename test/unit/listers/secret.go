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

package lister

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	clientcorev1 "k8s.io/client-go/listers/core/v1"
)

var _ clientcorev1.SecretLister = &FakeSecretLister{}
var _ clientcorev1.SecretNamespaceLister = &FakeSecretNamespaceLister{}

type FakeSecretLister struct {
	ListFn    func(selector labels.Selector) (ret []*corev1.Secret, err error)
	SecretsFn func(namespace string) clientcorev1.SecretNamespaceLister
}

type FakeSecretNamespaceLister struct {
	ListFn func(selector labels.Selector) (ret []*corev1.Secret, err error)
	GetFn  func(name string) (ret *corev1.Secret, err error)
}

func NewFakeSecretLister() *FakeSecretLister {
	return &FakeSecretLister{
		ListFn: func(selector labels.Selector) (ret []*corev1.Secret, err error) {
			return nil, nil
		},

		SecretsFn: func(namespace string) clientcorev1.SecretNamespaceLister {
			return nil
		},
	}
}

func NewFakeSecretNamespaceLister() *FakeSecretNamespaceLister {
	return &FakeSecretNamespaceLister{
		ListFn: func(selector labels.Selector) (ret []*corev1.Secret, err error) {
			return nil, nil
		},
		GetFn: func(name string) (ret *corev1.Secret, err error) {
			return nil, nil
		},
	}
}

func (f *FakeSecretLister) List(selector labels.Selector) (ret []*corev1.Secret, err error) {
	return f.ListFn(selector)
}

func (f *FakeSecretLister) Secrets(namespace string) clientcorev1.SecretNamespaceLister {
	return f.SecretsFn(namespace)
}

func (f *FakeSecretNamespaceLister) List(selector labels.Selector) (ret []*corev1.Secret, err error) {
	return f.ListFn(selector)
}

func (f *FakeSecretNamespaceLister) Get(name string) (*corev1.Secret, error) {
	return f.GetFn(name)
}
