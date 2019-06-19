/*
Copyright 2019 The Jetstack cert-manager contributors.

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
	"sync"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	logf "github.com/jetstack/cert-manager/pkg/logs"
)

type BaseController struct {
	// the root controller context, used when calling Register() on
	// the queueingController
	*Context

	// a reference to the root context for this controller, used
	// as a basis for other contexts and for logging
	ctx context.Context

	// the function that should be called when an item is popped
	// off the workqueue
	syncHandler func(ctx context.Context, key string) error

	// mustSync is a slice of informers that must have synced before
	// this controller can start
	mustSync []cache.InformerSynced
	// queue is a reference to the queue used to enqueue resources
	// to be processed
	queue workqueue.RateLimitingInterface
}

type queueingController interface {
	Register(*Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error)
	ProcessItem(ctx context.Context, key string) error
}

func HandleOwnedResourceNamespacedFunc(log logr.Logger, queue workqueue.RateLimitingInterface, ownerGVK schema.GroupVersionKind, get func(namespace, name string) (interface{}, error)) func(obj interface{}) {
	return func(obj interface{}) {
		log := log.WithName("handleOwnedResource")

		metaobj, ok := obj.(metav1.Object)
		if !ok {
			log.Error(nil, "item passed to handleOwnedResource does not implement metav1.Object")
			return
		}
		log = logf.WithResource(log, metaobj)

		ownerRefs := metaobj.GetOwnerReferences()
		for _, ref := range ownerRefs {
			log := log.WithValues(
				logf.RelatedResourceNamespaceKey, metaobj.GetNamespace(),
				logf.RelatedResourceNameKey, ref.Name,
				logf.RelatedResourceKindKey, ref.Kind,
			)

			// Parse the Group out of the OwnerReference to compare it to what was parsed out of the requested OwnerType
			refGV, err := schema.ParseGroupVersion(ref.APIVersion)
			if err != nil {
				log.Error(err, "could not parse OwnerReference GroupVersion")
				continue
			}

			if refGV.Group == ownerGVK.Group && ref.Kind == ownerGVK.Kind {
				// TODO: how to handle namespace of owner references?
				order, err := get(metaobj.GetNamespace(), ref.Name)
				if err != nil {
					log.Error(err, "error getting order referenced by resource")
					continue
				}
				objKey, err := KeyFunc(order)
				if err != nil {
					log.Error(err, "error computing key for resource")
					continue
				}
				queue.Add(objKey)
			}
		}
	}
}

// New creates a basic BaseController, setting the sync call to the one given
func New(ctx *Context, name string, qc queueingController) (*BaseController, error) {
	queue, mustSync, err := qc.Register(ctx)
	if err != nil {
		return nil, err
	}
	c := newPreRegistered(ctx, name, qc, queue, mustSync)
	return c, nil
}

func newPreRegistered(ctx *Context, name string, qc queueingController, queue workqueue.RateLimitingInterface, mustSync []cache.InformerSynced) *BaseController {
	return &BaseController{
		Context:     ctx,
		ctx:         logf.NewContext(ctx.RootContext, nil, name),
		syncHandler: qc.ProcessItem,
		mustSync:    mustSync,
		queue:       queue,
	}
}

// RunWith starts the controller loop, with an additional function to run alongside the loop
func (bc *BaseController) RunWith(function func(context.Context), duration time.Duration) Interface {
	return func(workers int, stopCh <-chan struct{}) error {
		ctx, cancel := context.WithCancel(bc.ctx)
		defer cancel()
		log := logf.FromContext(ctx)

		log.Info("starting control loop")
		// wait for all the informer caches we depend on are synced
		if !cache.WaitForCacheSync(stopCh, bc.mustSync...) {
			// TODO: replace with Errorf call to glog
			return fmt.Errorf("error waiting for informer caches to sync")
		}

		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			// TODO (@munnerz): make time.Second duration configurable
			go wait.Until(func() {
				defer wg.Done()
				bc.worker(ctx)
			}, time.Second, stopCh)
		}

		if function != nil {
			go wait.Until(func() { function(ctx) }, duration, stopCh)
		}

		<-stopCh
		log.Info("shutting down queue as workqueue signaled shutdown")
		bc.queue.ShutDown()
		log.V(logf.DebugLevel).Info("waiting for workers to exit...")
		wg.Wait()
		log.V(logf.DebugLevel).Info("workers exited")
		return nil
	}
}

// Run starts the controller loop
func (bc *BaseController) Run(workers int, stopCh <-chan struct{}) error {
	return bc.RunWith(nil, 0)(workers, stopCh)
}

func (bc *BaseController) worker(ctx context.Context) {
	log := logf.FromContext(bc.ctx)

	log.V(logf.DebugLevel).Info("starting worker")
	for {
		obj, shutdown := bc.queue.Get()
		if shutdown {
			break
		}

		var key string
		// use an inlined function so we can use defer
		func() {
			defer bc.queue.Done(obj)
			var ok bool
			if key, ok = obj.(string); !ok {
				return
			}
			log := log.WithValues("key", key)
			log.Info("syncing item")
			if err := bc.syncHandler(ctx, key); err != nil {
				log.Error(err, "re-queuing item  due to error processing")
				bc.queue.AddRateLimited(obj)
				return
			}
			log.Info("finished processing work item")
			bc.queue.Forget(obj)
		}()
	}
	log.V(logf.DebugLevel).Info("exiting worker loop")
}
