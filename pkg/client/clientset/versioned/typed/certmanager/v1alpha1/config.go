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

package v1alpha1

import (
	v1alpha1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	scheme "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// ConfigsGetter has a method to return a ConfigInterface.
// A group's client should implement this interface.
type ConfigsGetter interface {
	Configs(namespace string) ConfigInterface
}

// ConfigInterface has methods to work with Config resources.
type ConfigInterface interface {
	Create(*v1alpha1.Config) (*v1alpha1.Config, error)
	Update(*v1alpha1.Config) (*v1alpha1.Config, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v1alpha1.Config, error)
	List(opts v1.ListOptions) (*v1alpha1.ConfigList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.Config, err error)
	ConfigExpansion
}

// configs implements ConfigInterface
type configs struct {
	client rest.Interface
	ns     string
}

// newConfigs returns a Configs
func newConfigs(c *CertmanagerV1alpha1Client, namespace string) *configs {
	return &configs{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the config, and returns the corresponding config object, and an error if there is any.
func (c *configs) Get(name string, options v1.GetOptions) (result *v1alpha1.Config, err error) {
	result = &v1alpha1.Config{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("configs").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of Configs that match those selectors.
func (c *configs) List(opts v1.ListOptions) (result *v1alpha1.ConfigList, err error) {
	result = &v1alpha1.ConfigList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("configs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested configs.
func (c *configs) Watch(opts v1.ListOptions) (watch.Interface, error) {
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("configs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Watch()
}

// Create takes the representation of a config and creates it.  Returns the server's representation of the config, and an error, if there is any.
func (c *configs) Create(config *v1alpha1.Config) (result *v1alpha1.Config, err error) {
	result = &v1alpha1.Config{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("configs").
		Body(config).
		Do().
		Into(result)
	return
}

// Update takes the representation of a config and updates it. Returns the server's representation of the config, and an error, if there is any.
func (c *configs) Update(config *v1alpha1.Config) (result *v1alpha1.Config, err error) {
	result = &v1alpha1.Config{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("configs").
		Name(config.Name).
		Body(config).
		Do().
		Into(result)
	return
}

// Delete takes name of the config and deletes it. Returns an error if one occurs.
func (c *configs) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("configs").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *configs) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("configs").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched config.
func (c *configs) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.Config, err error) {
	result = &v1alpha1.Config{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("configs").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
