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

package discovery

import (
	openapi_v2 "github.com/google/gnostic/openapiv2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/openapi"
	restclient "k8s.io/client-go/rest"
)

var _ discovery.DiscoveryInterface = &Discovery{}

type Discovery struct {
	serverResourcesForGroupVersionFn     func(string) (*metav1.APIResourceList, error)
	serverResourcesFn                    func() ([]*metav1.APIResourceList, error)
	serverGroupsAndResourcesFn           func() ([]*metav1.APIGroup, []*metav1.APIResourceList, error)
	serverPreferredResourcesFn           func() ([]*metav1.APIResourceList, error)
	serverPreferredNamespacedResourcesFn func() ([]*metav1.APIResourceList, error)
	serverGroupsFn                       func() (*metav1.APIGroupList, error)
	serverVersionFn                      func() (*version.Info, error)
	openAPISchemaFn                      func() (*openapi_v2.Document, error)
	openAPIV3SchemaFn                    func() openapi.Client
	restClientFn                         func() restclient.Interface
}

func NewDiscovery() *Discovery {
	return &Discovery{
		serverResourcesForGroupVersionFn:     func(string) (*metav1.APIResourceList, error) { return nil, nil },
		serverResourcesFn:                    func() ([]*metav1.APIResourceList, error) { return nil, nil },
		serverGroupsAndResourcesFn:           func() ([]*metav1.APIGroup, []*metav1.APIResourceList, error) { return nil, nil, nil },
		serverPreferredResourcesFn:           func() ([]*metav1.APIResourceList, error) { return nil, nil },
		serverPreferredNamespacedResourcesFn: func() ([]*metav1.APIResourceList, error) { return nil, nil },
		serverGroupsFn:                       func() (*metav1.APIGroupList, error) { return nil, nil },
		serverVersionFn:                      func() (*version.Info, error) { return nil, nil },
		openAPISchemaFn:                      func() (*openapi_v2.Document, error) { return nil, nil },
		openAPIV3SchemaFn:                    func() openapi.Client { return nil },
		restClientFn:                         func() restclient.Interface { return nil },
	}
}

func (d *Discovery) WithServerGroups(fn func() (*metav1.APIGroupList, error)) *Discovery {
	d.serverGroupsFn = fn
	return d
}

func (d *Discovery) WithServerResourcesForGroupVersion(fn func(groupVersion string) (*metav1.APIResourceList, error)) *Discovery {
	d.serverResourcesForGroupVersionFn = fn
	return d
}

func (d *Discovery) ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error) {
	return d.serverResourcesForGroupVersionFn(groupVersion)
}

func (d *Discovery) ServerResources() ([]*metav1.APIResourceList, error) {
	return d.serverResourcesFn()
}

func (d *Discovery) ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	return d.serverGroupsAndResourcesFn()
}

func (d *Discovery) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	return d.serverPreferredResourcesFn()
}

func (d *Discovery) ServerPreferredNamespacedResources() ([]*metav1.APIResourceList, error) {
	return d.serverPreferredNamespacedResourcesFn()
}

func (d *Discovery) ServerGroups() (*metav1.APIGroupList, error) {
	return d.serverGroupsFn()
}

func (d *Discovery) ServerVersion() (*version.Info, error) {
	return d.serverVersionFn()
}

func (d *Discovery) OpenAPISchema() (*openapi_v2.Document, error) {
	return d.openAPISchemaFn()
}

func (d *Discovery) OpenAPIV3() openapi.Client {
	return d.openAPIV3SchemaFn()
}

func (d *Discovery) RESTClient() restclient.Interface {
	return d.restClientFn()
}
