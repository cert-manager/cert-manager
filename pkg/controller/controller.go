package controller

import (
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type Controller struct {
	Context *Context
	// TODO (@munnerz): come up with some way to swap out this queue type
	Queue     workqueue.RateLimitingInterface
	Worker    func(Context, interface{}) error
	Informers []cache.SharedIndexInformer
}

// Run will start this controllers run loop, with the specified number of
// worker goroutines. It will block until a message is placed onto the stopCh.
func (c *Controller) Run(workers int, stopCh <-chan struct{}) {
	defer c.Queue.ShutDown()

	hasSynced := make([]cache.InformerSynced, len(c.Informers))
	for i, informer := range c.Informers {
		informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: c.Queue.Add,
			UpdateFunc: func(old, cur interface{}) {
				if !reflect.DeepEqual(old, cur) {
					c.Queue.Add(cur)
				}
			},
			DeleteFunc: c.Queue.Add,
		})
		hasSynced[i] = informer.HasSynced
	}

	c.Context.Logger.Printf("Starting control loop")

	// wait for all the informer caches we depend on are synced
	if !cache.WaitForCacheSync(stopCh, hasSynced...) {
		c.Context.Logger.Errorf("error waiting for informer caches to sync")
		return
	}

	for i := 0; i < workers; i++ {
		// TODO (@munnerz): make time.Second duration configurable
		go wait.Until(c.worker, time.Second, stopCh)
	}

	<-stopCh
	c.Context.Logger.Printf("shutting down queue as workqueue signalled shutdown")
}

func (c *Controller) worker() {
	c.Context.Logger.Printf("starting worker")
	for {
		obj, shutdown := c.Queue.Get()
		if shutdown {
			break
		}

		err := func(obj interface{}) error {
			defer c.Queue.Done(obj)
			if err := c.Worker(*c.Context, obj); err != nil {
				return err
			}
			c.Queue.Forget(obj)
			return nil
		}(obj)

		if err != nil {
			c.Context.Logger.Printf("requeuing item due to error processing: %s", err.Error())
			c.Queue.AddRateLimited(obj)
		}

		c.Context.Logger.Printf("finished processing work item")
	}
	c.Context.Logger.Printf("exiting worker loop")
}
