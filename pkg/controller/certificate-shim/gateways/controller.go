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

package controller

import (
	"context"
	"fmt"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	gwlisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	shimhelper "github.com/cert-manager/cert-manager/pkg/controller/certificate-shim"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

const (
	ControllerName = "gateway-shim"
)

type controller struct {
	gatewayLister gwlisters.GatewayLister
	sync          shimhelper.SyncFn

	// For testing purposes.
	queue workqueue.RateLimitingInterface
}

func (c *controller) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	c.gatewayLister = ctx.GWShared.Gateway().V1().Gateways().Lister()
	log := logf.FromContext(ctx.RootContext, ControllerName)
	c.sync = shimhelper.SyncFnFor(ctx.Recorder, log, ctx.CMClient, ctx.SharedInformerFactory.Certmanager().V1().Certificates().Lister(), ctx.IngressShimOptions, ctx.FieldManager)

	// We don't need to requeue Gateways on "Deleted" events, since our Sync
	// function does nothing when the Gateway lister returns "not found". But we
	// still do it for consistency with the rest of the controllers.
	ctx.GWShared.Gateway().V1().Gateways().Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{
		Queue: c.queue,
	})

	// Even thought the Gateway controller already re-queues the Gateway after
	// creating a child Certificate, we still re-queue the Gateway when we
	// receive an "Add" event for the Certificate (the workqueue de-duplicates
	// keys, so we should not worry).
	//
	// Regarding "Update" events on Certificates, we need to requeue the parent
	// Gateway because we need to check if the Certificate is still up to date.
	//
	// Regarding "Deleted" events on Certificates, we requeue the parent Gateway
	// to immediately recreate the Certificate when the Certificate is deleted.
	ctx.SharedInformerFactory.Certmanager().V1().Certificates().Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		WorkFunc: certificateHandler(c.queue),
	})

	mustSync := []cache.InformerSynced{
		ctx.GWShared.Gateway().V1().Gateways().Informer().HasSynced,
		ctx.SharedInformerFactory.Certmanager().V1().Certificates().Informer().HasSynced,
	}

	return c.queue, mustSync, nil
}

func (c *controller) ProcessItem(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	gateway, err := c.gatewayLister.Gateways(namespace).Get(name)

	if err != nil {
		if k8sErrors.IsNotFound(err) {
			runtime.HandleError(fmt.Errorf("Gateway '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	return c.sync(ctx, gateway)
}

// Whenever a Certificate gets updated, added or deleted, we want to reconcile
// its parent Gateway. This parent Gateway is called "controller object". For
// example, the following Certificate "cert-1" is controlled by the Gateway
// "gateway-1":
//
//	kind: Certificate
//	metadata:                                           Note that the owner
//	  namespace: cert-1                                 reference does not
//	  ownerReferences:                                  have a namespace,
//	  - controller: true                                since owner refs
//	    apiVersion: networking.x-k8s.io/v1alpha1        only work inside
//	    kind: Gateway                                   the same namespace.
//	    name: gateway-1
//	    blockOwnerDeletion: true
//	    uid: 7d3897c2-ce27-4144-883a-e1b5f89bd65a
func certificateHandler(queue workqueue.RateLimitingInterface) func(obj interface{}) {
	return func(obj interface{}) {
		crt, ok := obj.(*cmapi.Certificate)
		if !ok {
			runtime.HandleError(fmt.Errorf("not a Certificate object: %#v", obj))
			return
		}

		ref := metav1.GetControllerOf(crt)
		if ref == nil {
			// No controller should care about orphans being deleted or
			// updated.
			return
		}

		// We don't check the apiVersion e.g. "networking.x-k8s.io/v1alpha1"
		// because there is no chance that another object called "Gateway" be
		// the controller of a Certificate.
		if ref.Kind != "Gateway" {
			return
		}

		queue.Add(crt.Namespace + "/" + ref.Name)
	}
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&controller{queue: workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), ControllerName)}).
			Complete()
	})
}
