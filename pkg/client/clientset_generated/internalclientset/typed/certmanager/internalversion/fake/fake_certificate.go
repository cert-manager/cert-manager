/*
Copyright 2017 The Kubernetes Authors.

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

package fake

import (
	certmanager "github.com/munnerz/cert-manager/pkg/apis/certmanager"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeCertificates implements CertificateInterface
type FakeCertificates struct {
	Fake *FakeCertmanager
	ns   string
}

var certificatesResource = schema.GroupVersionResource{Group: "certmanager.k8s.io", Version: "", Resource: "certificates"}

var certificatesKind = schema.GroupVersionKind{Group: "certmanager.k8s.io", Version: "", Kind: "Certificate"}

func (c *FakeCertificates) Create(certificate *certmanager.Certificate) (result *certmanager.Certificate, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(certificatesResource, c.ns, certificate), &certmanager.Certificate{})

	if obj == nil {
		return nil, err
	}
	return obj.(*certmanager.Certificate), err
}

func (c *FakeCertificates) Update(certificate *certmanager.Certificate) (result *certmanager.Certificate, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(certificatesResource, c.ns, certificate), &certmanager.Certificate{})

	if obj == nil {
		return nil, err
	}
	return obj.(*certmanager.Certificate), err
}

func (c *FakeCertificates) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(certificatesResource, c.ns, name), &certmanager.Certificate{})

	return err
}

func (c *FakeCertificates) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(certificatesResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &certmanager.CertificateList{})
	return err
}

func (c *FakeCertificates) Get(name string, options v1.GetOptions) (result *certmanager.Certificate, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(certificatesResource, c.ns, name), &certmanager.Certificate{})

	if obj == nil {
		return nil, err
	}
	return obj.(*certmanager.Certificate), err
}

func (c *FakeCertificates) List(opts v1.ListOptions) (result *certmanager.CertificateList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(certificatesResource, certificatesKind, c.ns, opts), &certmanager.CertificateList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &certmanager.CertificateList{}
	for _, item := range obj.(*certmanager.CertificateList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested certificates.
func (c *FakeCertificates) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(certificatesResource, c.ns, opts))

}

// Patch applies the patch and returns the patched certificate.
func (c *FakeCertificates) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *certmanager.Certificate, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(certificatesResource, c.ns, name, data, subresources...), &certmanager.Certificate{})

	if obj == nil {
		return nil, err
	}
	return obj.(*certmanager.Certificate), err
}
