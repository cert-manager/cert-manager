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

package ingress

import (
	"context"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	listersv1 "k8s.io/client-go/listers/networking/v1"
)

type v1Lister struct {
	lister listersv1.IngressLister
}

type v1NamespaceLister struct {
	nsLister listersv1.IngressNamespaceLister
}

func (l *v1Lister) List(selector labels.Selector) ([]*networkingv1.Ingress, error) {
	return l.lister.List(selector)
}

func (l *v1Lister) Ingresses(namespace string) InternalIngressNamespaceLister {
	return &v1NamespaceLister{nsLister: l.lister.Ingresses(namespace)}
}

func (nl *v1NamespaceLister) List(selector labels.Selector) ([]*networkingv1.Ingress, error) {
	return nl.nsLister.List(selector)
}

func (nl *v1NamespaceLister) Get(name string) (*networkingv1.Ingress, error) {
	return nl.nsLister.Get(name)
}

type v1CreaterUpdater struct {
	client kubernetes.Interface
}

func (v1 *v1CreaterUpdater) Ingresses(namespace string) InternalIngressInterface {
	return &v1Interface{
		client: v1.client,
		ns:     namespace,
	}
}

type v1Interface struct {
	client kubernetes.Interface
	ns     string
}

func (v1 *v1Interface) Create(ctx context.Context, ingress *networkingv1.Ingress, opts metav1.CreateOptions) (*networkingv1.Ingress, error) {
	return v1.client.NetworkingV1().Ingresses(v1.ns).Create(ctx, ingress, opts)
}

func (v1 *v1Interface) Update(ctx context.Context, ingress *networkingv1.Ingress, opts metav1.UpdateOptions) (*networkingv1.Ingress, error) {
	return v1.client.NetworkingV1().Ingresses(v1.ns).Update(ctx, ingress, opts)
}

func (v1 *v1Interface) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return v1.client.NetworkingV1().Ingresses(v1.ns).Delete(ctx, name, opts)
}
