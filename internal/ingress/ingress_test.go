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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	networkingv1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/informers"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/pointer"

	"github.com/cert-manager/cert-manager/pkg/controller"
	discoveryfake "github.com/cert-manager/cert-manager/test/unit/discovery"
)

// Important: these tests cannot run in parallel as the cache holds internal state at the package level.

func TestFunctionalityAgainstV1(t *testing.T) {
	// wipe known versions cache
	cacheLock.Lock()
	knownAPIVersionCache.Store(make(map[string]bool))
	cacheLock.Unlock()

	fakeClient := kubefake.NewSimpleClientset()
	v1ctx := &controller.Context{
		RootContext:               context.TODO(),
		Client:                    fakeClient,
		DiscoveryClient:           fakeDiscoveryFor(networkingv1.SchemeGroupVersion),
		KubeSharedInformerFactory: informers.NewSharedInformerFactory(fakeClient, 10*time.Hour),
	}
	ch := make(chan struct{})
	v1ctx.KubeSharedInformerFactory.Start(ch)
	errs := testFunctionality(t, v1ctx)
	assert.Len(t, errs, 0, "InternalIngress should not fail on an API server that supports networking.k8s.io/v1")
	close(ch)
}

func TestFunctionalityAgainstV1Beta1(t *testing.T) {
	cacheLock.Lock()
	knownAPIVersionCache.Store(make(map[string]bool))
	cacheLock.Unlock()

	fakeClient := kubefake.NewSimpleClientset()

	v1beta1ctx := &controller.Context{
		RootContext:               context.TODO(),
		Client:                    fakeClient,
		DiscoveryClient:           fakeDiscoveryFor(networkingv1beta1.SchemeGroupVersion),
		KubeSharedInformerFactory: informers.NewSharedInformerFactory(fakeClient, 10*time.Hour),
	}
	ch := make(chan struct{})
	v1beta1ctx.KubeSharedInformerFactory.Start(ch)
	errs := testFunctionality(t, v1beta1ctx)
	assert.Len(t, errs, 0, "InternalIngress should not fail on an API server that supports networking.k8s.io/v1beta1")
	close(ch)
}

func TestFunctionalityAgainstNone(t *testing.T) {
	// wipe known versions cache
	cacheLock.Lock()
	knownAPIVersionCache.Store(make(map[string]bool))
	cacheLock.Unlock()

	fakeClient := kubefake.NewSimpleClientset()
	noneCtx := &controller.Context{
		RootContext:               context.TODO(),
		Client:                    fakeClient,
		DiscoveryClient:           uselessDiscovery(),
		KubeSharedInformerFactory: informers.NewSharedInformerFactory(fakeClient, 10*time.Hour),
	}
	_, _, err := NewListerInformer(noneCtx)
	if assert.Error(t, err) {
		assert.Equal(
			t,
			fmt.Errorf("neither %s nor %s have any APIResources", networkingv1.SchemeGroupVersion, networkingv1beta1.SchemeGroupVersion),
			err,
		)
	}
}

func fakeDiscoveryFor(version schema.GroupVersion) *discoveryfake.Discovery {
	return discoveryfake.NewDiscovery().WithServerResourcesForGroupVersion(func(groupVersion string) (*metav1.APIResourceList, error) {
		if groupVersion == version.String() {
			return &metav1.APIResourceList{
				TypeMeta:     metav1.TypeMeta{},
				GroupVersion: version.String(),
				APIResources: []metav1.APIResource{
					{
						Name:               "ingresses",
						SingularName:       "Ingress",
						Namespaced:         true,
						Group:              version.Group,
						Version:            version.Version,
						Kind:               version.WithKind("Ingress").Kind,
						Verbs:              metav1.Verbs{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"},
						ShortNames:         []string{"ing"},
						Categories:         []string{"all"},
						StorageVersionHash: "testing",
					},
				},
			}, nil
		} else {
			return &metav1.APIResourceList{}, nil
		}
	})
}

func uselessDiscovery() *discoveryfake.Discovery {
	return discoveryfake.NewDiscovery().
		WithServerResourcesForGroupVersion(
			func(groupVersion string) (*metav1.APIResourceList, error) {
				return &metav1.APIResourceList{}, nil
			},
		)
}

func testFunctionality(t *testing.T, ctx *controller.Context) []error {
	var ret []error
	lister, _, err := NewListerInformer(ctx)
	assert.NoError(t, err, "New ListerInformer should not fail")
	if err != nil {
		ret = append(ret, err)
	}
	createUpdater, err := NewCreateUpdater(ctx)
	assert.NoError(t, err, "New CreateUpdater should not fail")
	if err != nil {
		ret = append(ret, err)
	}
	_, err = createUpdater.Ingresses("default").Create(context.TODO(), &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: pointer.StringPtr("test1"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "test",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: func() *networkingv1.PathType { s := networkingv1.PathTypePrefix; return &s }(),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "test",
											Port: networkingv1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}, metav1.CreateOptions{})
	assert.NoError(t, err, "Create should not fail")
	if err != nil {
		ret = append(ret, err)
	}
	_, err = createUpdater.Ingresses("default").Update(context.TODO(), &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: pointer.StringPtr("test1"),
			Rules: []networkingv1.IngressRule{
				{
					Host: "test",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: func() *networkingv1.PathType { s := networkingv1.PathTypePrefix; return &s }(),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "test",
											Port: networkingv1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}, metav1.UpdateOptions{})
	assert.NoError(t, err, "Update should not fail")
	if err != nil {
		ret = append(ret, err)
	}
	_, err = lister.List(labels.Everything())
	assert.NoError(t, err, "List should not fail")

	err = createUpdater.Ingresses("default").Delete(context.TODO(), "test", metav1.DeleteOptions{})
	assert.NoError(t, err, "delete should not fail")
	if err != nil {
		ret = append(ret, err)
	}
	return ret
}
