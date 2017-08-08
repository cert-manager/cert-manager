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
	certmanager "github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeIssuers implements IssuerInterface
type FakeIssuers struct {
	Fake *FakeCertmanager
	ns   string
}

var issuersResource = schema.GroupVersionResource{Group: "certmanager", Version: "", Resource: "issuers"}

var issuersKind = schema.GroupVersionKind{Group: "certmanager", Version: "", Kind: "Issuer"}

func (c *FakeIssuers) Create(issuer *certmanager.Issuer) (result *certmanager.Issuer, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(issuersResource, c.ns, issuer), &certmanager.Issuer{})

	if obj == nil {
		return nil, err
	}
	return obj.(*certmanager.Issuer), err
}

func (c *FakeIssuers) Update(issuer *certmanager.Issuer) (result *certmanager.Issuer, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(issuersResource, c.ns, issuer), &certmanager.Issuer{})

	if obj == nil {
		return nil, err
	}
	return obj.(*certmanager.Issuer), err
}

func (c *FakeIssuers) UpdateStatus(issuer *certmanager.Issuer) (*certmanager.Issuer, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(issuersResource, "status", c.ns, issuer), &certmanager.Issuer{})

	if obj == nil {
		return nil, err
	}
	return obj.(*certmanager.Issuer), err
}

func (c *FakeIssuers) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(issuersResource, c.ns, name), &certmanager.Issuer{})

	return err
}

func (c *FakeIssuers) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(issuersResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &certmanager.IssuerList{})
	return err
}

func (c *FakeIssuers) Get(name string, options v1.GetOptions) (result *certmanager.Issuer, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(issuersResource, c.ns, name), &certmanager.Issuer{})

	if obj == nil {
		return nil, err
	}
	return obj.(*certmanager.Issuer), err
}

func (c *FakeIssuers) List(opts v1.ListOptions) (result *certmanager.IssuerList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(issuersResource, issuersKind, c.ns, opts), &certmanager.IssuerList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &certmanager.IssuerList{}
	for _, item := range obj.(*certmanager.IssuerList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested issuers.
func (c *FakeIssuers) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(issuersResource, c.ns, opts))

}

// Patch applies the patch and returns the patched issuer.
func (c *FakeIssuers) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *certmanager.Issuer, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(issuersResource, c.ns, name, data, subresources...), &certmanager.Issuer{})

	if obj == nil {
		return nil, err
	}
	return obj.(*certmanager.Issuer), err
}
