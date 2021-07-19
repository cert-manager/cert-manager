/*
Copyright 2021 The cert-manager Authors.

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

// Package ingress lets us use an internal type for supporting multiple kinds of ingresses
package ingress

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	networkingv1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/cache"

	"github.com/jetstack/cert-manager/pkg/controller"
)

// keep an internal cache of known API types so calls to the discovery API are kept to a minimum
// https://pkg.go.dev/sync/atomic#example-Value-ReadMostly
var (
	knownAPIVersionCache atomic.Value
	cacheLock            sync.Mutex
)

// InternalIngressCreateUpdater mimics a client-go networking/v1 or
// networking/v1beta1 Interface.
type InternalIngressCreateUpdater interface {
	Ingresses(namespace string) InternalIngressInterface
}

// InternalIngressInterface mimics a client-go networking/v1/IngressInterface
// It always returns a *networkingv1.Ingress, so when implementing this you must convert any type of
// Ingress into a v1.Ingress.
type InternalIngressInterface interface {
	Create(ctx context.Context, ingress *networkingv1.Ingress, opts metav1.CreateOptions) (*networkingv1.Ingress, error)
	Update(ctx context.Context, ingress *networkingv1.Ingress, opts metav1.UpdateOptions) (*networkingv1.Ingress, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
}

// InternalIngressLister mimics a client-go networking/v1/IngressLister.
type InternalIngressLister interface {
	List(selector labels.Selector) (ret []*networkingv1.Ingress, err error)
	Ingresses(namespace string) InternalIngressNamespaceLister
}

// InternalIngressNamespaceLister mimics a client-go networking/v1/IngressNamespaceLister
type InternalIngressNamespaceLister interface {
	List(selector labels.Selector) (ret []*networkingv1.Ingress, err error)
	Get(name string) (*networkingv1.Ingress, error)
}

// NewListerInformer returns an InternalIngressLister configured for v1 or v1beta1 ingresses depending on the
// API Versions available in the discovery client.
func NewListerInformer(ctx *controller.Context) (InternalIngressLister, cache.SharedIndexInformer, error) {
	if hasVersion(ctx.DiscoveryClient, networkingv1.SchemeGroupVersion.String()) {
		return &v1Lister{
				lister: ctx.KubeSharedInformerFactory.Networking().V1().Ingresses().Lister(),
			},
			ctx.KubeSharedInformerFactory.Networking().V1().Ingresses().Informer(),
			nil
	} else if hasVersion(ctx.DiscoveryClient, networkingv1beta1.SchemeGroupVersion.String()) {
		sch := runtime.NewScheme()
		clientgoscheme.AddToScheme(sch)
		return &v1beta1Lister{
				scheme: sch,
				lister: ctx.KubeSharedInformerFactory.Networking().V1beta1().Ingresses().Lister(),
			},
			ctx.KubeSharedInformerFactory.Networking().V1beta1().Ingresses().Informer(),
			nil
	}
	return nil, nil, fmt.Errorf("neither %s or %s have any APIResources", networkingv1.SchemeGroupVersion, networkingv1beta1.SchemeGroupVersion)
}

// NewCreateUpdater returns an InternalIngressCreateUpdater configured for v1 or v1beta1 ingresses depending on the
// versions available in the discovery client
func NewCreateUpdater(ctx *controller.Context, discoveryOverrides ...discovery.DiscoveryInterface) (InternalIngressCreateUpdater, error) {
	if hasVersion(ctx.DiscoveryClient, networkingv1.SchemeGroupVersion.String()) {
		return &v1CreaterUpdater{
			client: ctx.Client,
		}, nil
	} else if hasVersion(ctx.DiscoveryClient, networkingv1beta1.SchemeGroupVersion.String()) {
		sch := runtime.NewScheme()
		clientgoscheme.AddToScheme(sch)
		return &v1beta1CreaterUpdater{
			client: ctx.Client,
			scheme: sch,
		}, nil
	} else {
		return nil, fmt.Errorf("neither %s or %s have any APIResources", networkingv1.SchemeGroupVersion, networkingv1beta1.SchemeGroupVersion)
	}
}

func hasVersion(d discovery.DiscoveryInterface, GroupVersion string) bool {
	// check whether the GroupVersion is already known
	knownVersions := knownAPIVersionCache.Load().(map[string]bool)
	if knownVersions[GroupVersion] == true {
		return true
	}

	resourceList, err := d.ServerResourcesForGroupVersion(GroupVersion)
	if err != nil {
		return false
	}
	if len(resourceList.APIResources) > 0 {
		// Now we know the APIServer supports this GroupVersion, store the result atomically
		// in the knownVersions cache. Lock, get the latest copy, atomically update.
		cacheLock.Lock()
		defer cacheLock.Unlock()
		oldCache := knownAPIVersionCache.Load().(map[string]bool)
		newCache := make(map[string]bool)
		for k, v := range oldCache {
			newCache[k] = v
		}
		newCache[GroupVersion] = true
		knownAPIVersionCache.Store(newCache)
		return true
	}
	return false
}

func init() {
	knownAPIVersionCache.Store(make(map[string]bool))
}
