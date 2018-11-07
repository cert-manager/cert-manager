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
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// ConfigLister helps list Configs.
type ConfigLister interface {
	// List lists all Configs in the indexer.
	List(selector labels.Selector) (ret []*v1alpha1.Config, err error)
	// Configs returns an object that can list and get Configs.
	Configs(namespace string) ConfigNamespaceLister
	ConfigListerExpansion
}

// configLister implements the ConfigLister interface.
type configLister struct {
	indexer cache.Indexer
}

// NewConfigLister returns a new ConfigLister.
func NewConfigLister(indexer cache.Indexer) ConfigLister {
	return &configLister{indexer: indexer}
}

// List lists all Configs in the indexer.
func (s *configLister) List(selector labels.Selector) (ret []*v1alpha1.Config, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.Config))
	})
	return ret, err
}

// Configs returns an object that can list and get Configs.
func (s *configLister) Configs(namespace string) ConfigNamespaceLister {
	return configNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// ConfigNamespaceLister helps list and get Configs.
type ConfigNamespaceLister interface {
	// List lists all Configs in the indexer for a given namespace.
	List(selector labels.Selector) (ret []*v1alpha1.Config, err error)
	// Get retrieves the Config from the indexer for a given namespace and name.
	Get(name string) (*v1alpha1.Config, error)
	ConfigNamespaceListerExpansion
}

// configNamespaceLister implements the ConfigNamespaceLister
// interface.
type configNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all Configs in the indexer for a given namespace.
func (s configNamespaceLister) List(selector labels.Selector) (ret []*v1alpha1.Config, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.Config))
	})
	return ret, err
}

// Get retrieves the Config from the indexer for a given namespace and name.
func (s configNamespaceLister) Get(name string) (*v1alpha1.Config, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("config"), name)
	}
	return obj.(*v1alpha1.Config), nil
}
