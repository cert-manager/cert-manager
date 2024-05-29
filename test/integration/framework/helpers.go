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

package framework

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"k8s.io/kubectl/pkg/util/openapi"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	certmgrscheme "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/scheme"
	cminformers "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
)

func NewEventRecorder(t *testing.T, scheme *runtime.Scheme) record.EventRecorder {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(t.Logf)
	return eventBroadcaster.NewRecorder(scheme, corev1.EventSource{Component: t.Name()})
}

func NewClients(t *testing.T, config *rest.Config) (kubernetes.Interface, internalinformers.KubeInformerFactory, cmclient.Interface, cminformers.SharedInformerFactory, *runtime.Scheme) {
	httpClient, err := rest.HTTPClientFor(config)
	if err != nil {
		t.Fatal(err)
	}

	cl, err := kubernetes.NewForConfigAndClient(config, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	factory := internalinformers.NewBaseKubeInformerFactory(cl, 0, "")

	cmCl, err := cmclient.NewForConfigAndClient(config, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	cmFactory := cminformers.NewSharedInformerFactory(cmCl, 0)

	scheme := runtime.NewScheme()
	kscheme.AddToScheme(scheme)
	certmgrscheme.AddToScheme(scheme)
	apiext.AddToScheme(scheme)
	apireg.AddToScheme(scheme)
	gwapi.Install(scheme)

	return cl, factory, cmCl, cmFactory, scheme
}

func StartInformersAndController(t *testing.T, factory internalinformers.KubeInformerFactory, cmFactory cminformers.SharedInformerFactory, c controllerpkg.Interface) StopFunc {
	return StartInformersAndControllers(t, factory, cmFactory, c)
}

func StartInformersAndControllers(t *testing.T, factory internalinformers.KubeInformerFactory, cmFactory cminformers.SharedInformerFactory, cs ...controllerpkg.Interface) StopFunc {
	rootCtx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error)

	factory.Start(rootCtx.Done())
	cmFactory.Start(rootCtx.Done())
	group, _ := errgroup.WithContext(context.Background())
	go func() {
		defer close(errCh)
		for _, c := range cs {
			func(c controllerpkg.Interface) {
				group.Go(func() error {
					return c.Run(1, rootCtx)
				})
			}(c)
		}
		errCh <- group.Wait()
	}()
	return func() {
		cancel()
		err := <-errCh
		if err != nil {
			t.Fatal(err)
		}
	}
}

func WaitForOpenAPIResourcesToBeLoaded(t *testing.T, ctx context.Context, config *rest.Config, gvk schema.GroupVersionKind) {
	dc, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	err = wait.PollUntilContextCancel(ctx, time.Second, true, func(ctx context.Context) (done bool, err error) {
		og := openapi.NewOpenAPIGetter(dc)
		oapiResource, err := openapi.NewOpenAPIParser(og).Parse()
		if err != nil {
			return false, err
		}

		if oapiResource.LookupResource(gvk) != nil {
			return true, nil
		}
		return false, nil
	})

	if err != nil {
		t.Fatal("Our GVK isn't loaded into the OpenAPI resources API after waiting for 2 minutes", err)
	}
}
