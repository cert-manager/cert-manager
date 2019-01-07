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
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

var (
	KeyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc
)

func DefaultItemBasedRateLimiter() workqueue.RateLimiter {
	return workqueue.NewItemExponentialFailureRateLimiter(time.Second*5, time.Minute*5)
}

// QueuingEventHandler is an implementation of cache.ResourceEventHandler that
// simply queues objects that are added/updated/deleted.
type QueuingEventHandler struct {
	Queue workqueue.RateLimitingInterface
}

func (q *QueuingEventHandler) Enqueue(obj interface{}) {
	key, err := KeyFunc(obj)
	if err != nil {
		runtime.HandleError(err)
		return
	}
	q.Queue.Add(key)
}

func (q *QueuingEventHandler) OnAdd(obj interface{}) {
	q.Enqueue(obj)
}

func (q *QueuingEventHandler) OnUpdate(old, new interface{}) {
	if reflect.DeepEqual(old, new) {
		return
	}
	q.Enqueue(new)
}

func (q *QueuingEventHandler) OnDelete(obj interface{}) {
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = tombstone.Obj
	}
	q.Enqueue(obj)
}

// BlockingEventHandler is an implementation of cache.ResourceEventHandler that
// simply synchronously calls it's WorkFunc upon calls to OnAdd, OnUpdate or
// OnDelete.
type BlockingEventHandler struct {
	WorkFunc func(obj interface{})
}

func (b *BlockingEventHandler) Enqueue(obj interface{}) {
	b.WorkFunc(obj)
}

func (b *BlockingEventHandler) OnAdd(obj interface{}) {
	b.WorkFunc(obj)
}

func (b *BlockingEventHandler) OnUpdate(old, new interface{}) {
	if reflect.DeepEqual(old, new) {
		return
	}
	b.WorkFunc(new)
}

func (b *BlockingEventHandler) OnDelete(obj interface{}) {
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = tombstone.Obj
	}
	b.WorkFunc(obj)
}
