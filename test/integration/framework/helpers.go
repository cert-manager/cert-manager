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
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/kubectl/pkg/util/openapi"

	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cminformers "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
)

func NewEventRecorder(t *testing.T) record.EventRecorder {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(t.Logf)
	return eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: t.Name()})
}

func NewClients(t *testing.T, config *rest.Config) (kubernetes.Interface, informers.SharedInformerFactory, cmclient.Interface, cminformers.SharedInformerFactory) {
	cl, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	factory := informers.NewSharedInformerFactory(cl, 0)
	cmCl, err := cmclient.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	cmFactory := cminformers.NewSharedInformerFactory(cmCl, 0)
	return cl, factory, cmCl, cmFactory
}

func StartInformersAndController(t *testing.T, factory informers.SharedInformerFactory, cmFactory cminformers.SharedInformerFactory, c controllerpkg.Interface) StopFunc {
	return StartInformersAndControllers(t, factory, cmFactory, c)
}

func StartInformersAndControllers(t *testing.T, factory informers.SharedInformerFactory, cmFactory cminformers.SharedInformerFactory, cs ...controllerpkg.Interface) StopFunc {
	stopCh := make(chan struct{})
	errCh := make(chan error)

	factory.Start(stopCh)
	cmFactory.Start(stopCh)
	group, _ := errgroup.WithContext(context.Background())
	go func() {
		defer close(errCh)
		for _, c := range cs {
			func(c controllerpkg.Interface) {
				group.Go(func() error {
					return c.Run(1, stopCh)
				})
			}(c)
		}
		errCh <- group.Wait()
	}()
	return func() {
		close(stopCh)
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

	err = wait.PollImmediateUntil(time.Second, func() (bool, error) {
		og := openapi.NewOpenAPIGetter(dc)
		oapiResource, err := openapi.NewOpenAPIParser(og).Parse()
		if err != nil {
			return false, err
		}

		if oapiResource.LookupResource(gvk) != nil {
			return true, nil
		}
		return false, nil
	}, ctx.Done())

	if err != nil {
		t.Fatal("Our GVK isn't loaded into the OpenAPI resources API after waiting for 2 minutes", err)
	}
}
