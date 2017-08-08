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

package internalversion

import (
	certmanager "github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager"
	scheme "github.com/jetstack-experimental/cert-manager/pkg/client/internalclientset/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// IssuersGetter has a method to return a IssuerInterface.
// A group's client should implement this interface.
type IssuersGetter interface {
	Issuers(namespace string) IssuerInterface
}

// IssuerInterface has methods to work with Issuer resources.
type IssuerInterface interface {
	Create(*certmanager.Issuer) (*certmanager.Issuer, error)
	Update(*certmanager.Issuer) (*certmanager.Issuer, error)
	UpdateStatus(*certmanager.Issuer) (*certmanager.Issuer, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*certmanager.Issuer, error)
	List(opts v1.ListOptions) (*certmanager.IssuerList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *certmanager.Issuer, err error)
	IssuerExpansion
}

// issuers implements IssuerInterface
type issuers struct {
	client rest.Interface
	ns     string
}

// newIssuers returns a Issuers
func newIssuers(c *CertmanagerClient, namespace string) *issuers {
	return &issuers{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Create takes the representation of a issuer and creates it.  Returns the server's representation of the issuer, and an error, if there is any.
func (c *issuers) Create(issuer *certmanager.Issuer) (result *certmanager.Issuer, err error) {
	result = &certmanager.Issuer{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("issuers").
		Body(issuer).
		Do().
		Into(result)
	return
}

// Update takes the representation of a issuer and updates it. Returns the server's representation of the issuer, and an error, if there is any.
func (c *issuers) Update(issuer *certmanager.Issuer) (result *certmanager.Issuer, err error) {
	result = &certmanager.Issuer{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("issuers").
		Name(issuer.Name).
		Body(issuer).
		Do().
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclientstatus=false comment above the type to avoid generating UpdateStatus().

func (c *issuers) UpdateStatus(issuer *certmanager.Issuer) (result *certmanager.Issuer, err error) {
	result = &certmanager.Issuer{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("issuers").
		Name(issuer.Name).
		SubResource("status").
		Body(issuer).
		Do().
		Into(result)
	return
}

// Delete takes name of the issuer and deletes it. Returns an error if one occurs.
func (c *issuers) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("issuers").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *issuers) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("issuers").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Body(options).
		Do().
		Error()
}

// Get takes name of the issuer, and returns the corresponding issuer object, and an error if there is any.
func (c *issuers) Get(name string, options v1.GetOptions) (result *certmanager.Issuer, err error) {
	result = &certmanager.Issuer{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("issuers").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of Issuers that match those selectors.
func (c *issuers) List(opts v1.ListOptions) (result *certmanager.IssuerList, err error) {
	result = &certmanager.IssuerList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("issuers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested issuers.
func (c *issuers) Watch(opts v1.ListOptions) (watch.Interface, error) {
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("issuers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Watch()
}

// Patch applies the patch and returns the patched issuer.
func (c *issuers) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *certmanager.Issuer, err error) {
	result = &certmanager.Issuer{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("issuers").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
