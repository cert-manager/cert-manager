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
package v1alpha1

import (
	v1alpha1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	scheme "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// ACMEValidationsGetter has a method to return a ACMEValidationInterface.
// A group's client should implement this interface.
type ACMEValidationsGetter interface {
	ACMEValidations(namespace string) ACMEValidationInterface
}

// ACMEValidationInterface has methods to work with ACMEValidation resources.
type ACMEValidationInterface interface {
	Create(*v1alpha1.ACMEValidation) (*v1alpha1.ACMEValidation, error)
	Update(*v1alpha1.ACMEValidation) (*v1alpha1.ACMEValidation, error)
	UpdateStatus(*v1alpha1.ACMEValidation) (*v1alpha1.ACMEValidation, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v1alpha1.ACMEValidation, error)
	List(opts v1.ListOptions) (*v1alpha1.ACMEValidationList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.ACMEValidation, err error)
	ACMEValidationExpansion
}

// aCMEValidations implements ACMEValidationInterface
type aCMEValidations struct {
	client rest.Interface
	ns     string
}

// newACMEValidations returns a ACMEValidations
func newACMEValidations(c *CertmanagerV1alpha1Client, namespace string) *aCMEValidations {
	return &aCMEValidations{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the aCMEValidation, and returns the corresponding aCMEValidation object, and an error if there is any.
func (c *aCMEValidations) Get(name string, options v1.GetOptions) (result *v1alpha1.ACMEValidation, err error) {
	result = &v1alpha1.ACMEValidation{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("acmevalidations").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of ACMEValidations that match those selectors.
func (c *aCMEValidations) List(opts v1.ListOptions) (result *v1alpha1.ACMEValidationList, err error) {
	result = &v1alpha1.ACMEValidationList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("acmevalidations").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested aCMEValidations.
func (c *aCMEValidations) Watch(opts v1.ListOptions) (watch.Interface, error) {
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("acmevalidations").
		VersionedParams(&opts, scheme.ParameterCodec).
		Watch()
}

// Create takes the representation of a aCMEValidation and creates it.  Returns the server's representation of the aCMEValidation, and an error, if there is any.
func (c *aCMEValidations) Create(aCMEValidation *v1alpha1.ACMEValidation) (result *v1alpha1.ACMEValidation, err error) {
	result = &v1alpha1.ACMEValidation{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("acmevalidations").
		Body(aCMEValidation).
		Do().
		Into(result)
	return
}

// Update takes the representation of a aCMEValidation and updates it. Returns the server's representation of the aCMEValidation, and an error, if there is any.
func (c *aCMEValidations) Update(aCMEValidation *v1alpha1.ACMEValidation) (result *v1alpha1.ACMEValidation, err error) {
	result = &v1alpha1.ACMEValidation{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("acmevalidations").
		Name(aCMEValidation.Name).
		Body(aCMEValidation).
		Do().
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().

func (c *aCMEValidations) UpdateStatus(aCMEValidation *v1alpha1.ACMEValidation) (result *v1alpha1.ACMEValidation, err error) {
	result = &v1alpha1.ACMEValidation{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("acmevalidations").
		Name(aCMEValidation.Name).
		SubResource("status").
		Body(aCMEValidation).
		Do().
		Into(result)
	return
}

// Delete takes name of the aCMEValidation and deletes it. Returns an error if one occurs.
func (c *aCMEValidations) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("acmevalidations").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *aCMEValidations) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("acmevalidations").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched aCMEValidation.
func (c *aCMEValidations) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.ACMEValidation, err error) {
	result = &v1alpha1.ACMEValidation{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("acmevalidations").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
