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
	time "time"

	certmanager_v1alpha1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	versioned "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	internalinterfaces "github.com/jetstack/cert-manager/pkg/client/informers/externalversions/internalinterfaces"
	v1alpha1 "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// ConfigInformer provides access to a shared informer and lister for
// Configs.
type ConfigInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.ConfigLister
}

type configInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewConfigInformer constructs a new informer for Config type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewConfigInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredConfigInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredConfigInformer constructs a new informer for Config type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredConfigInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CertmanagerV1alpha1().Configs(namespace).List(options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CertmanagerV1alpha1().Configs(namespace).Watch(options)
			},
		},
		&certmanager_v1alpha1.Config{},
		resyncPeriod,
		indexers,
	)
}

func (f *configInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredConfigInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *configInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&certmanager_v1alpha1.Config{}, f.defaultInformer)
}

func (f *configInformer) Lister() v1alpha1.ConfigLister {
	return v1alpha1.NewConfigLister(f.Informer().GetIndexer())
}
