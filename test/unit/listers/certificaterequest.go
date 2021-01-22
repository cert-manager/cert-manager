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
	"k8s.io/apimachinery/pkg/labels"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmlist "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1"
)

type FakeCertificateRequestLister struct {
	ListFn                func(labels.Selector) ([]*cmapi.CertificateRequest, error)
	CertificateRequestsFn func(namespace string) cmlist.CertificateRequestNamespaceLister
}

type FakeCertificateRequestNamespaceLister struct {
	ListFn func(labels.Selector) ([]*cmapi.CertificateRequest, error)
	GetFn  func(name string) (*cmapi.CertificateRequest, error)
}

func NewFakeCertificateRequestLister() *FakeCertificateRequestLister {
	return &FakeCertificateRequestLister{
		ListFn: func(selector labels.Selector) (ret []*cmapi.CertificateRequest, err error) {
			return nil, nil
		},

		CertificateRequestsFn: func(namespace string) cmlist.CertificateRequestNamespaceLister {
			return nil
		},
	}
}

func (f *FakeCertificateRequestLister) WithCertificateRequests(fn func(namespace string) cmlist.CertificateRequestNamespaceLister) *FakeCertificateRequestLister {
	f.CertificateRequestsFn = fn
	return f
}

func NewFakeCertificateRequestNamespaceLister() *FakeCertificateRequestNamespaceLister {
	return &FakeCertificateRequestNamespaceLister{
		ListFn: func(selector labels.Selector) (ret []*cmapi.CertificateRequest, err error) {
			return nil, nil
		},
		GetFn: func(name string) (ret *cmapi.CertificateRequest, err error) {
			return nil, nil
		},
	}
}

func (f *FakeCertificateRequestNamespaceLister) WithList(fn func(_ labels.Selector) ([]*cmapi.CertificateRequest, error)) *FakeCertificateRequestNamespaceLister {
	f.ListFn = fn
	return f
}

func (f *FakeCertificateRequestLister) List(selector labels.Selector) (ret []*cmapi.CertificateRequest, err error) {
	return f.ListFn(selector)
}

func (f *FakeCertificateRequestLister) CertificateRequests(namespace string) cmlist.CertificateRequestNamespaceLister {
	return f.CertificateRequestsFn(namespace)
}

func (f *FakeCertificateRequestNamespaceLister) List(selector labels.Selector) (ret []*cmapi.CertificateRequest, err error) {
	return f.ListFn(selector)
}

func (f *FakeCertificateRequestNamespaceLister) Get(name string) (*cmapi.CertificateRequest, error) {
	return f.GetFn(name)
}
