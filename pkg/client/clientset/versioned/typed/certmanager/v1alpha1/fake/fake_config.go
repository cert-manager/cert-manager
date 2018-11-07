/*
Copyright 2018 The Jetstack cert-manager contributors.

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

// FakeConfigs implements ConfigInterface
type FakeConfigs struct {
	Fake *FakeCertmanagerV1alpha1
	ns   string
}

var configsResource = schema.GroupVersionResource{Group: "certmanager.k8s.io", Version: "v1alpha1", Resource: "configs"}

var configsKind = schema.GroupVersionKind{Group: "certmanager.k8s.io", Version: "v1alpha1", Kind: "Config"}

// Get takes name of the config, and returns the corresponding config object, and an error if there is any.
func (c *FakeConfigs) Get(name string, options v1.GetOptions) (result *v1alpha1.Config, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(configsResource, c.ns, name), &v1alpha1.Config{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Config), err
}

// List takes label and field selectors, and returns the list of Configs that match those selectors.
func (c *FakeConfigs) List(opts v1.ListOptions) (result *v1alpha1.ConfigList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(configsResource, configsKind, c.ns, opts), &v1alpha1.ConfigList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.ConfigList{}
	for _, item := range obj.(*v1alpha1.ConfigList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested configs.
func (c *FakeConfigs) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(configsResource, c.ns, opts))

}

// Create takes the representation of a config and creates it.  Returns the server's representation of the config, and an error, if there is any.
func (c *FakeConfigs) Create(config *v1alpha1.Config) (result *v1alpha1.Config, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(configsResource, c.ns, config), &v1alpha1.Config{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Config), err
}

// Update takes the representation of a config and updates it. Returns the server's representation of the config, and an error, if there is any.
func (c *FakeConfigs) Update(config *v1alpha1.Config) (result *v1alpha1.Config, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(configsResource, c.ns, config), &v1alpha1.Config{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Config), err
}

// Delete takes name of the config and deletes it. Returns an error if one occurs.
func (c *FakeConfigs) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(configsResource, c.ns, name), &v1alpha1.Config{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeConfigs) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(configsResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &v1alpha1.ConfigList{})
	return err
}

// Patch applies the patch and returns the patched config.
func (c *FakeConfigs) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.Config, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(configsResource, c.ns, name, data, subresources...), &v1alpha1.Config{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Config), err
}
