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
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	listersv1beta1 "k8s.io/client-go/listers/networking/v1beta1"
)

const ConvertedGVKAnnotation = `internal.cert-manager.io/converted-gvk`

type v1beta1Lister struct {
	scheme *runtime.Scheme
	lister listersv1beta1.IngressLister
}

type v1beta1NamespaceLister struct {
	scheme   *runtime.Scheme
	nsLister listersv1beta1.IngressNamespaceLister
}

func (l *v1beta1Lister) List(selector labels.Selector) ([]*networkingv1.Ingress, error) {
	all, err := l.lister.List(selector)
	if err != nil {
		return nil, err
	}
	return convertV1Beta1ListToV1(all, l.scheme)
}

func (l *v1beta1Lister) Ingresses(namespace string) InternalIngressNamespaceLister {
	return &v1beta1NamespaceLister{
		scheme:   l.scheme,
		nsLister: l.lister.Ingresses(namespace),
	}
}

func (nl *v1beta1NamespaceLister) List(selector labels.Selector) ([]*networkingv1.Ingress, error) {
	all, err := nl.nsLister.List(selector)
	if err != nil {
		return nil, err
	}
	return convertV1Beta1ListToV1(all, nl.scheme)
}

func (nl *v1beta1NamespaceLister) Get(name string) (*networkingv1.Ingress, error) {
	ing, err := nl.nsLister.Get(name)
	if err != nil {
		return nil, err
	}
	return convertV1Beta1ToV1(ing, nl.scheme)
}

func convertV1Beta1ListToV1(list []*networkingv1beta1.Ingress, scheme *runtime.Scheme) ([]*networkingv1.Ingress, error) {
	var ret []*networkingv1.Ingress
	for _, in := range list {
		out, err := convertV1Beta1ToV1(in, scheme)
		if err != nil {
			return nil, err
		}
		ret = append(ret, out)
	}
	return ret, nil
}

func convertV1Beta1ToV1(in *networkingv1beta1.Ingress, scheme *runtime.Scheme) (*networkingv1.Ingress, error) {
	out, err := scheme.ConvertToVersion(in, networkingv1.SchemeGroupVersion)
	if err != nil {
		return nil, err
	}
	v1Ingress, ok := out.(*networkingv1.Ingress)
	if !ok {
		return nil, fmt.Errorf(
			"could not convert %s to %s when processing object %s/%s",
			networkingv1beta1.SchemeGroupVersion,
			networkingv1.SchemeGroupVersion,
			in.Namespace,
			in.Name)
	}
	v1Ingress.Annotations[ConvertedGVKAnnotation] = networkingv1beta1.SchemeGroupVersion.WithKind("Ingress").String()
	return v1Ingress, nil
}

func convertV1ToV1Beta1(in *networkingv1.Ingress, scheme *runtime.Scheme) (*networkingv1beta1.Ingress, error) {
	out, err := scheme.ConvertToVersion(in, networkingv1beta1.SchemeGroupVersion)
	if err != nil {
		return nil, err
	}
	v1Beta1Ingress, ok := out.(*networkingv1beta1.Ingress)
	if !ok {
		return nil, fmt.Errorf(
			"could not convert %s to %s when processing object %s/%s",
			networkingv1beta1.SchemeGroupVersion,
			networkingv1.SchemeGroupVersion,
			in.Namespace,
			in.Name)
	}
	return v1Beta1Ingress, nil
}

type v1beta1CreaterUpdater struct {
	scheme *runtime.Scheme
	client kubernetes.Interface
}

func (v *v1beta1CreaterUpdater) Ingresses(namespace string) InternalIngressInterface {
	return &v1beta1Interface{
		client: v.client,
		ns:     namespace,
		scheme: v.scheme,
	}
}

type v1beta1Interface struct {
	scheme *runtime.Scheme
	client kubernetes.Interface
	ns     string
}

func (v *v1beta1Interface) Create(ctx context.Context, ingress *networkingv1.Ingress, opts metav1.CreateOptions) (*networkingv1.Ingress, error) {
	ing, err := convertV1ToV1Beta1(ingress, v.scheme)
	if err != nil {
		return nil, err
	}
	newIng, err := v.client.NetworkingV1beta1().Ingresses(v.ns).Create(ctx, ing, opts)
	if err != nil {
		return nil, err
	}
	return convertV1Beta1ToV1(newIng, v.scheme)
}

func (v *v1beta1Interface) Update(ctx context.Context, ingress *networkingv1.Ingress, opts metav1.UpdateOptions) (*networkingv1.Ingress, error) {
	ing, err := convertV1ToV1Beta1(ingress, v.scheme)
	if err != nil {
		return nil, err
	}
	newIng, err := v.client.NetworkingV1beta1().Ingresses(v.ns).Update(ctx, ing, opts)
	if err != nil {
		return nil, err
	}
	return convertV1Beta1ToV1(newIng, v.scheme)
}

func (v *v1beta1Interface) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return v.client.NetworkingV1beta1().Ingresses(v.ns).Delete(ctx, name, opts)
}
