package controller

import (
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type Base struct {
	Context Context
	// TODO (@munnerz): come up with some way to swap out this queue type
	Queue  workqueue.RateLimitingInterface
	Worker func() bool

	hasSynced []cache.InformerSynced
}

func (b *Base) AddHandler(informer cache.SharedIndexInformer) {
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: b.Queue.Add,
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				b.Queue.Add(cur)
			}
		},
		DeleteFunc: b.Queue.Add,
	})
	b.hasSynced = append(b.hasSynced, informer.HasSynced)
}

// Run will start this controllers run loop, with the specified number of
// worker goroutines. It will block until a message is placed onto the stopCh.
func (b *Base) Run(workers int, stopCh <-chan struct{}) {
	defer b.Queue.ShutDown()

	b.Context.Logger.Printf("Starting control loop")

	// wait for all the informer caches we depend on are synced
	if !cache.WaitForCacheSync(stopCh, b.hasSynced...) {
		b.Context.Logger.Errorf("error waiting for informer caches to sync")
		return
	}

	for i := 0; i < workers; i++ {
		// TODO (@munnerz): make time.Second duration configurable
		go wait.Until(b.worker, time.Second, stopCh)
	}

	<-stopCh
	b.Context.Logger.Printf("shutting down queue as workqueue signalled shutdown")
}

func (b *Base) worker() {
	b.Context.Logger.Printf("starting worker")
	for b.Worker() {
		b.Context.Logger.Printf("finished processing work item")
	}
	b.Context.Logger.Printf("exiting worker loop")
}
