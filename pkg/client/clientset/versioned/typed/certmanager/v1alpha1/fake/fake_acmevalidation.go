/*
Copyright 2018 Jetstack Ltd.

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

// FakeACMEValidations implements ACMEValidationInterface
type FakeACMEValidations struct {
	Fake *FakeCertmanagerV1alpha1
	ns   string
}

var acmevalidationsResource = schema.GroupVersionResource{Group: "certmanager.k8s.io", Version: "v1alpha1", Resource: "acmevalidations"}

var acmevalidationsKind = schema.GroupVersionKind{Group: "certmanager.k8s.io", Version: "v1alpha1", Kind: "ACMEValidation"}

// Get takes name of the aCMEValidation, and returns the corresponding aCMEValidation object, and an error if there is any.
func (c *FakeACMEValidations) Get(name string, options v1.GetOptions) (result *v1alpha1.ACMEValidation, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(acmevalidationsResource, c.ns, name), &v1alpha1.ACMEValidation{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ACMEValidation), err
}

// List takes label and field selectors, and returns the list of ACMEValidations that match those selectors.
func (c *FakeACMEValidations) List(opts v1.ListOptions) (result *v1alpha1.ACMEValidationList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(acmevalidationsResource, acmevalidationsKind, c.ns, opts), &v1alpha1.ACMEValidationList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.ACMEValidationList{}
	for _, item := range obj.(*v1alpha1.ACMEValidationList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested aCMEValidations.
func (c *FakeACMEValidations) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(acmevalidationsResource, c.ns, opts))

}

// Create takes the representation of a aCMEValidation and creates it.  Returns the server's representation of the aCMEValidation, and an error, if there is any.
func (c *FakeACMEValidations) Create(aCMEValidation *v1alpha1.ACMEValidation) (result *v1alpha1.ACMEValidation, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(acmevalidationsResource, c.ns, aCMEValidation), &v1alpha1.ACMEValidation{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ACMEValidation), err
}

// Update takes the representation of a aCMEValidation and updates it. Returns the server's representation of the aCMEValidation, and an error, if there is any.
func (c *FakeACMEValidations) Update(aCMEValidation *v1alpha1.ACMEValidation) (result *v1alpha1.ACMEValidation, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(acmevalidationsResource, c.ns, aCMEValidation), &v1alpha1.ACMEValidation{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ACMEValidation), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeACMEValidations) UpdateStatus(aCMEValidation *v1alpha1.ACMEValidation) (*v1alpha1.ACMEValidation, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(acmevalidationsResource, "status", c.ns, aCMEValidation), &v1alpha1.ACMEValidation{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ACMEValidation), err
}

// Delete takes name of the aCMEValidation and deletes it. Returns an error if one occurs.
func (c *FakeACMEValidations) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(acmevalidationsResource, c.ns, name), &v1alpha1.ACMEValidation{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeACMEValidations) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(acmevalidationsResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &v1alpha1.ACMEValidationList{})
	return err
}

// Patch applies the patch and returns the patched aCMEValidation.
func (c *FakeACMEValidations) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.ACMEValidation, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(acmevalidationsResource, c.ns, name, data, subresources...), &v1alpha1.ACMEValidation{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ACMEValidation), err
}
