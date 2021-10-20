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

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	shimhelper "github.com/jetstack/cert-manager/pkg/controller/certificate-shim"
	"github.com/jetstack/cert-manager/pkg/internal/ingress"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

const (
	ControllerName = "ingress-shim"
)

type controller struct {
	ingressLister ingress.InternalIngressLister
	sync          shimhelper.SyncFn
}

func (c *controller) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	cmShared := ctx.SharedInformerFactory

	internalIngressLister, internalIngressInformer, err := ingress.NewListerInformer(ctx)
	if err != nil {
		return nil, nil, err
	}

	c.ingressLister = internalIngressLister

	log := logf.FromContext(ctx.RootContext, ControllerName)
	c.sync = shimhelper.SyncFnFor(ctx.Recorder, log, ctx.CMClient, cmShared.Certmanager().V1().Certificates().Lister(), ctx.IngressShimOptions)

	queue := workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), ControllerName)

	mustSync := []cache.InformerSynced{
		internalIngressInformer.HasSynced,
		cmShared.Certmanager().V1().Certificates().Informer().HasSynced,
	}

	// We still requeue on "Deleted" for consistency with the rest of the
	// controllers, but we don't actually need to. "Deleted" is only emitted
	// after the apiserver has removed the object entirely from etcd; if we had
	// to do some cleanup, we would use a finalizer, and the cleanup logic would
	// be triggered by the "Updated" event when the object gets marked for
	// deletion.
	internalIngressInformer.AddEventHandler(&controllerpkg.QueuingEventHandler{
		Queue: queue,
	})

	// We still re-queue on "Add" because the workqueue will remove any
	// duplicate key, although the Ingress controller already re-queues the
	// Ingress after creating the Certificate.
	//
	// We re-queue on "Update" because we need to check if the Certificate is
	// still up to date.
	//
	// We want to immediately recreate a Certificate when the Certificate is
	// deleted.
	cmShared.Certmanager().V1().Certificates().Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		WorkFunc: certificateHandler(queue),
	})

	return queue, mustSync, nil
}

func (c *controller) ProcessItem(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	crt, err := c.ingressLister.Ingresses(namespace).Get(name)

	if err != nil {
		if k8sErrors.IsNotFound(err) {
			runtime.HandleError(fmt.Errorf("ingress '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	return c.sync(ctx, crt)
}

// Whenever a Certificate gets updated, added or deleted, we want to reconcile
// its parent Ingress. This parent Ingress is called "controller object". For
// example, the following Certificate "cert-1" is controlled by the Ingress
// "ingress-1":
//
//     kind: Certificate
//     metadata:                                           Note that the owner
//       namespace: cert-1                                 reference does not
//       ownerReferences:                                  have a namespace,
//       - controller: true                                since owner refs
//         apiVersion: networking.k8s.io/v1beta1           only work inside
//         kind: Ingress                                   the same namespace.
//         name: ingress-1
//         blockOwnerDeletion: true
//         uid: 7d3897c2-ce27-4144-883a-e1b5f89bd65a
func certificateHandler(queue workqueue.RateLimitingInterface) func(obj interface{}) {
	return func(obj interface{}) {
		cert, ok := obj.(*cmapi.Certificate)
		if !ok {
			runtime.HandleError(fmt.Errorf("not a Certificate object: %#v", obj))
			return
		}

		ingress := metav1.GetControllerOf(cert)
		if ingress == nil {
			// No controller should care about orphans being deleted or
			// updated.
			return
		}

		// We don't check the apiVersion e.g. "networking.k8s.io/v1beta1"
		// because there is no chance that another object called "Ingress" be
		// the controller of a Certificate.
		if ingress.Kind != "Ingress" {
			return
		}

		queue.Add(cert.Namespace + "/" + ingress.Name)
	}
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&controller{}).
			Complete()
	})
}
