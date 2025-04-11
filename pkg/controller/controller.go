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
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
)

type runFunc func(context.Context)

type runDurationFunc struct {
	fn       runFunc
	duration time.Duration
}

type queueingController interface {
	Register(*Context) (workqueue.TypedRateLimitingInterface[types.NamespacedName], []cache.InformerSynced, error)
	ProcessItem(ctx context.Context, key types.NamespacedName) error
}

func NewController(
	name string,
	metrics *metrics.Metrics,
	syncFunc func(ctx context.Context, key types.NamespacedName) error,
	mustSync []cache.InformerSynced,
	runDurationFuncs []runDurationFunc,
	queue workqueue.TypedRateLimitingInterface[types.NamespacedName],
) Interface {
	return &controller{
		name:             name,
		metrics:          metrics,
		syncHandler:      syncFunc,
		mustSync:         mustSync,
		runDurationFuncs: runDurationFuncs,
		queue:            queue,
	}
}

type controller struct {
	// name is the name for this controller
	name string

	// the function that should be called when an item is popped
	// off the workqueue
	syncHandler func(ctx context.Context, key types.NamespacedName) error

	// mustSync is a slice of informers that must have synced before
	// this controller can start
	mustSync []cache.InformerSynced

	// a set of functions that will be called just after controller initialisation, once.
	runFirstFuncs []runFunc

	// a set of functions that should be called every duration.
	runDurationFuncs []runDurationFunc

	// queue is a reference to the queue used to enqueue resources
	// to be processed
	queue workqueue.TypedRateLimitingInterface[types.NamespacedName]

	// metrics is used to expose Prometheus, shared by all controllers
	metrics *metrics.Metrics
}

// Run starts the controller loop
func (c *controller) Run(workers int, ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log := logf.FromContext(ctx, c.name)

	log.V(logf.DebugLevel).Info("starting control loop")
	// wait for all the informer caches we depend on are synced
	if !cache.WaitForCacheSync(ctx.Done(), c.mustSync...) {
		return fmt.Errorf("error waiting for informer caches to sync")
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.worker(ctx)
		}()
	}

	for _, f := range c.runFirstFuncs {
		f(ctx)
	}

	for _, f := range c.runDurationFuncs {
		go wait.Until(func() { f.fn(ctx) }, f.duration, ctx.Done())
	}

	<-ctx.Done()
	log.V(logf.InfoLevel).Info("shutting down queue as workqueue signaled shutdown")
	c.queue.ShutDown()
	log.V(logf.DebugLevel).Info("waiting for workers to exit...")
	wg.Wait()
	log.V(logf.DebugLevel).Info("workers exited")
	return nil
}

func (c *controller) worker(ctx context.Context) {
	log := logf.FromContext(ctx)

	log.V(logf.DebugLevel).Info("starting worker")
	for {
		obj, shutdown := c.queue.Get()
		if shutdown {
			break
		}

		// use an inlined function so we can use defer
		func() {
			defer c.queue.Done(obj)

			log.V(logf.DebugLevel).Info("syncing item")

			// Increase sync count for this controller
			c.metrics.IncrementSyncCallCount(c.name)

			err := c.syncHandler(ctx, obj)
			if err != nil {
				if strings.Contains(err.Error(), genericregistry.OptimisticLockErrorMsg) {
					log.Info("re-queuing item due to optimistic locking on resource", "error", err.Error())
					// These errors are not counted towards the controllerSyncErrorCount metric on purpose
					// as they will go way with
					// https://github.com/cert-manager/cert-manager/blob/master/design/20220118.server-side-apply.md
				} else {
					log.Error(err, "re-queuing item due to error processing")
					c.metrics.IncrementSyncErrorCount(c.name)
				}

				c.queue.AddRateLimited(obj)
				return
			}
			log.V(logf.DebugLevel).Info("finished processing work item")
			c.queue.Forget(obj)
		}()
	}
	log.V(logf.DebugLevel).Info("exiting worker loop")
}
