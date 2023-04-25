/*
Copyright 2023 The cert-manager Authors.

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

package informers

import (
	"time"

	corev1 "k8s.io/api/core/v1"
	kubeinformers "k8s.io/client-go/informers"
	certificatesv1 "k8s.io/client-go/informers/certificates/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	networkingv1informers "k8s.io/client-go/informers/networking/v1"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

// This file contains an implementation of core informers that wraps the core
// upstream informers without any custom modifications

// baseFactory is an implementation of KubeSharedInformerFactory that returns
// standard upstream informer functionality
type baseFactory struct {
	f kubeinformers.SharedInformerFactory
	// namespace is set if cert-manager controller is scoped to a single
	// namespace
	namespace string
}

func NewBaseKubeInformerFactory(client kubernetes.Interface, resync time.Duration, namespace string) KubeInformerFactory {
	return &baseFactory{
		f: kubeinformers.NewSharedInformerFactoryWithOptions(client, resync, kubeinformers.WithNamespace(namespace)),
		// namespace is set to a non-empty value if cert-manager
		// controller is scoped to a single namespace via --namespace
		// flag
		namespace: namespace,
	}
}

func (bf *baseFactory) Start(stopCh <-chan struct{}) {
	bf.f.Start(stopCh)
}

func (bf *baseFactory) WaitForCacheSync(stopCh <-chan struct{}) map[string]bool {
	ret := make(map[string]bool)
	cacheSyncs := bf.f.WaitForCacheSync(stopCh)
	for key, val := range cacheSyncs {
		ret[key.String()] = val
	}
	return ret
}

func (bf *baseFactory) Ingresses() networkingv1informers.IngressInformer {
	return bf.f.Networking().V1().Ingresses()
}

func (bf *baseFactory) Secrets() SecretInformer {
	return &baseSecretInformer{
		f:         bf.f,
		namespace: bf.namespace,
	}
}

func (bf *baseFactory) CertificateSigningRequests() certificatesv1.CertificateSigningRequestInformer {
	return bf.f.Certificates().V1().CertificateSigningRequests()
}

var _ SecretInformer = &baseSecretInformer{}

// baseSecretInformer is an implementation of SecretInformer that only uses
// upstream client-go functionality
type baseSecretInformer struct {
	f         kubeinformers.SharedInformerFactory
	informer  cache.SharedIndexInformer
	namespace string
}

func (bsi *baseSecretInformer) Informer() Informer {
	bsi.informer = bsi.f.InformerFor(&corev1.Secret{}, bsi.new)
	return bsi.informer
}

func (bsi *baseSecretInformer) Lister() SecretLister {
	return corev1listers.NewSecretLister(bsi.f.InformerFor(&corev1.Secret{}, bsi.new).GetIndexer())
}

func (bsi *baseSecretInformer) new(client kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return corev1informers.NewSecretInformer(client, bsi.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
}
