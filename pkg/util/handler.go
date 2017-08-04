package util

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type QueueHandler interface {
	cache.ResourceEventHandler

	// Enqueue will add an object to this handlers queue, using the configured
	// key function to translate the object into a string
	Enqueue(interface{})
	// KeyFunc should accept an interface and return a string representation
	// for it. This string must uniquely identify the object given. If the
	// object cannot be in some way encoded into a string, an error is returned
	KeyFunc(interface{}) (string, error)
	// ObjForKey performs the reverse of KeyFunc. It looks up an object for a
	// given key, or an error otherwise.
	ObjForKey(string) (interface{}, error)
}

// QueueingEventHandler is an implementation of QueueHandler that uses a
// Kubernetes rate limited workqueue to process items. The KeyFunc used is by
// default the DeletionHandlingMetaNamespaceKeyFunc from client-go.
type QueueingEventHandler struct {
	Queue   workqueue.RateLimitingInterface
	GetFunc func(string, string) (interface{}, error)
}

var _ QueueHandler = &QueueingEventHandler{}

// Enqueue adds an objecgt given by obj onto the workqueue. It will key the
// object using the handlers KeyFunc.
func (q *QueueingEventHandler) Enqueue(obj interface{}) {
	key, err := q.KeyFunc(obj)
	if err != nil {
		runtime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err))
		return
	}
	q.Queue.Add(key)
}

// KeyFunc will return a namespace/name string for a given object, or an error
// if the object is not valid.
func (q *QueueingEventHandler) KeyFunc(obj interface{}) (string, error) {
	return cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
}

func (q *QueueingEventHandler) ObjForKey(key string) (interface{}, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, err
	}
	return q.GetFunc(namespace, name)
}

func (q *QueueingEventHandler) OnAdd(obj interface{}) {
	q.Enqueue(obj)
}

func (q *QueueingEventHandler) OnUpdate(oldObj, newObj interface{}) {
	q.Enqueue(newObj)
}

func (q *QueueingEventHandler) OnDelete(obj interface{}) {
	q.Enqueue(obj)
}
