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
	"k8s.io/client-go/kubernetes"
	listersv1beta1 "k8s.io/client-go/listers/networking/v1beta1"
)

const ConvertedGVKAnnotation = `internal.cert-manager.io/converted-gvk`

type v1beta1Lister struct {
	lister listersv1beta1.IngressLister
}

type v1beta1NamespaceLister struct {
	nsLister listersv1beta1.IngressNamespaceLister
}

func (l *v1beta1Lister) List(selector labels.Selector) ([]*networkingv1.Ingress, error) {
	all, err := l.lister.List(selector)
	if err != nil {
		return nil, err
	}
	return convertV1Beta1ListToV1(all)
}

func (l *v1beta1Lister) Ingresses(namespace string) InternalIngressNamespaceLister {
	return &v1beta1NamespaceLister{
		nsLister: l.lister.Ingresses(namespace),
	}
}

func (nl *v1beta1NamespaceLister) List(selector labels.Selector) ([]*networkingv1.Ingress, error) {
	all, err := nl.nsLister.List(selector)
	if err != nil {
		return nil, err
	}
	return convertV1Beta1ListToV1(all)
}

func (nl *v1beta1NamespaceLister) Get(name string) (*networkingv1.Ingress, error) {
	ing, err := nl.nsLister.Get(name)
	if err != nil {
		return nil, err
	}
	return convertV1Beta1ToV1(ing)
}

func convertV1Beta1ListToV1(list []*networkingv1beta1.Ingress) ([]*networkingv1.Ingress, error) {
	var ret []*networkingv1.Ingress
	for _, in := range list {
		out, err := convertV1Beta1ToV1(in)
		if err != nil {
			return nil, err
		}
		ret = append(ret, out)
	}
	return ret, nil
}

func convertV1Beta1ToV1(in *networkingv1beta1.Ingress) (*networkingv1.Ingress, error) {
	out := new(networkingv1.Ingress)
	err := Convert_v1beta1_Ingress_To_networking_Ingress(in.DeepCopy(), out, nil)

	if err != nil {
		return nil, fmt.Errorf(
			"could not convert %s to %s when processing object %s/%s: %w",
			networkingv1beta1.SchemeGroupVersion,
			networkingv1.SchemeGroupVersion,
			in.Namespace,
			in.Name,
			err,
		)
	}
	if out.Annotations == nil {
		out.Annotations = make(map[string]string)
	}
	out.Annotations[ConvertedGVKAnnotation] = networkingv1beta1.SchemeGroupVersion.WithKind("Ingress").String()
	return out, nil
}

func convertV1ToV1Beta1(in *networkingv1.Ingress) (*networkingv1beta1.Ingress, error) {
	out := new(networkingv1beta1.Ingress)
	err := Convert_networking_Ingress_To_v1beta1_Ingress(in.DeepCopy(), out, nil)
	if err != nil {
		return nil, fmt.Errorf(
			"could not convert %s to %s when processing object %s/%s: %w",
			networkingv1.SchemeGroupVersion,
			networkingv1beta1.SchemeGroupVersion,
			in.Namespace,
			in.Name,
			err,
		)
	}
	return out, nil
}

type v1beta1CreaterUpdater struct {
	client kubernetes.Interface
}

func (v *v1beta1CreaterUpdater) Ingresses(namespace string) InternalIngressInterface {
	return &v1beta1Interface{
		client: v.client,
		ns:     namespace,
	}
}

type v1beta1Interface struct {
	client kubernetes.Interface
	ns     string
}

func (v *v1beta1Interface) Get(ctx context.Context, name string, opts metav1.GetOptions) (*networkingv1.Ingress, error) {
	ing, err := v.client.NetworkingV1beta1().Ingresses(v.ns).Get(ctx, name, opts)
	if err != nil {
		return nil, err
	}
	return convertV1Beta1ToV1(ing)
}

func (v *v1beta1Interface) Create(ctx context.Context, ingress *networkingv1.Ingress, opts metav1.CreateOptions) (*networkingv1.Ingress, error) {
	ing, err := convertV1ToV1Beta1(ingress)
	if err != nil {
		return nil, err
	}
	newIng, err := v.client.NetworkingV1beta1().Ingresses(v.ns).Create(ctx, ing, opts)
	if err != nil {
		return nil, err
	}
	return convertV1Beta1ToV1(newIng)
}

func (v *v1beta1Interface) Update(ctx context.Context, ingress *networkingv1.Ingress, opts metav1.UpdateOptions) (*networkingv1.Ingress, error) {
	ing, err := convertV1ToV1Beta1(ingress)
	if err != nil {
		return nil, err
	}
	newIng, err := v.client.NetworkingV1beta1().Ingresses(v.ns).Update(ctx, ing, opts)
	if err != nil {
		return nil, err
	}
	return convertV1Beta1ToV1(newIng)
}

func (v *v1beta1Interface) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return v.client.NetworkingV1beta1().Ingresses(v.ns).Delete(ctx, name, opts)
}
