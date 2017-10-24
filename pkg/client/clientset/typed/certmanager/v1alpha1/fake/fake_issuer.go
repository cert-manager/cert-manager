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
	v1alpha1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeIssuers implements IssuerInterface
type FakeIssuers struct {
	Fake *FakeCertmanagerV1alpha1
	ns   string
}

var issuersResource = schema.GroupVersionResource{Group: "certmanager.k8s.io", Version: "v1alpha1", Resource: "issuers"}

var issuersKind = schema.GroupVersionKind{Group: "certmanager.k8s.io", Version: "v1alpha1", Kind: "Issuer"}

// Get takes name of the issuer, and returns the corresponding issuer object, and an error if there is any.
func (c *FakeIssuers) Get(name string, options v1.GetOptions) (result *v1alpha1.Issuer, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(issuersResource, c.ns, name), &v1alpha1.Issuer{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Issuer), err
}

// List takes label and field selectors, and returns the list of Issuers that match those selectors.
func (c *FakeIssuers) List(opts v1.ListOptions) (result *v1alpha1.IssuerList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(issuersResource, issuersKind, c.ns, opts), &v1alpha1.IssuerList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.IssuerList{}
	for _, item := range obj.(*v1alpha1.IssuerList).Items {
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

// Create takes the representation of a issuer and creates it.  Returns the server's representation of the issuer, and an error, if there is any.
func (c *FakeIssuers) Create(issuer *v1alpha1.Issuer) (result *v1alpha1.Issuer, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(issuersResource, c.ns, issuer), &v1alpha1.Issuer{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Issuer), err
}

// Update takes the representation of a issuer and updates it. Returns the server's representation of the issuer, and an error, if there is any.
func (c *FakeIssuers) Update(issuer *v1alpha1.Issuer) (result *v1alpha1.Issuer, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(issuersResource, c.ns, issuer), &v1alpha1.Issuer{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Issuer), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeIssuers) UpdateStatus(issuer *v1alpha1.Issuer) (*v1alpha1.Issuer, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(issuersResource, "status", c.ns, issuer), &v1alpha1.Issuer{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Issuer), err
}

// Delete takes name of the issuer and deletes it. Returns an error if one occurs.
func (c *FakeIssuers) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(issuersResource, c.ns, name), &v1alpha1.Issuer{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeIssuers) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(issuersResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &v1alpha1.IssuerList{})
	return err
}

// Patch applies the patch and returns the patched issuer.
func (c *FakeIssuers) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.Issuer, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(issuersResource, c.ns, name, data, subresources...), &v1alpha1.Issuer{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Issuer), err
}
