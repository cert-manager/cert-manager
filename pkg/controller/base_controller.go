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

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	logf "github.com/jetstack/cert-manager/pkg/logs"
)

type BaseController struct {
	// the controllers root context, containing a controller scoped logger
	Ctx context.Context
	*Context

	// To allow injection for testing.
	syncHandler func(ctx context.Context, key string) error

	watchedInformers []cache.InformerSynced
	Queue            workqueue.RateLimitingInterface
}

func New(ctx *Context, controllerName string, syncHandler func(ctx context.Context, key string) error) *BaseController {
	bctrl := &BaseController{Context: ctx}
	bctrl.syncHandler = syncHandler
	bctrl.Ctx = logf.NewContext(ctx.RootContext, nil, controllerName)
	return bctrl
}

func (bctrl *BaseController) AddQueuing(rateLimiter workqueue.RateLimiter, name string, informer cache.SharedIndexInformer) {
	bctrl.Queue = workqueue.NewNamedRateLimitingQueue(rateLimiter, name)
	informer.AddEventHandler(&QueuingEventHandler{Queue: bctrl.Queue})
	bctrl.watchedInformers = append(bctrl.watchedInformers, informer.HasSynced)
}

func (bctrl *BaseController) AddHandled(informer cache.SharedIndexInformer, handler cache.ResourceEventHandler) {
	informer.AddEventHandler(handler)
	bctrl.watchedInformers = append(bctrl.watchedInformers, informer.HasSynced)
}

func (bctrl *BaseController) AddWatched(informers ...cache.SharedIndexInformer) {
	for _, informer := range informers {
		bctrl.watchedInformers = append(bctrl.watchedInformers, informer.HasSynced)
	}
}

func (bc *BaseController) RunWith(function func(context.Context), duration time.Duration, workers int, stopCh <-chan struct{}) error {
	ctx, cancel := context.WithCancel(bc.Ctx)
	defer cancel()
	log := logf.FromContext(ctx)

	log.Info("starting control loop")
	// wait for all the informer caches we depend on are synced
	if !cache.WaitForCacheSync(stopCh, bc.watchedInformers...) {
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
	bc.Queue.ShutDown()
	log.V(logf.DebugLevel).Info("waiting for workers to exit...")
	wg.Wait()
	log.V(logf.DebugLevel).Info("workers exited")
	return nil
}

func (bc *BaseController) Run(workers int, stopCh <-chan struct{}) error {
	return bc.RunWith(nil, 0, workers, stopCh)
}

func (bc *BaseController) worker(ctx context.Context) {
	log := logf.FromContext(bc.Ctx)

	log.V(logf.DebugLevel).Info("starting worker")
	for {
		obj, shutdown := bc.Queue.Get()
		if shutdown {
			break
		}

		var key string
		// use an inlined function so we can use defer
		func() {
			defer bc.Queue.Done(obj)
			var ok bool
			if key, ok = obj.(string); !ok {
				return
			}
			log := log.WithValues("key", key)
			log.Info("syncing item")
			if err := bc.syncHandler(ctx, key); err != nil {
				log.Error(err, "re-queuing item  due to error processing")
				bc.Queue.AddRateLimited(obj)
				return
			}
			log.Info("finished processing work item")
			bc.Queue.Forget(obj)
		}()
	}
	log.V(logf.DebugLevel).Info("exiting worker loop")
}
