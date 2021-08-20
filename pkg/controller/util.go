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
	"reflect"
	"strings"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	logf "github.com/jetstack/cert-manager/pkg/logs"
)

var (
	// KeyFunc creates a key for an API object. The key can be passed to a
	// worker function that processes an object from a queue such as
	// ProcessItem.
	KeyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc
)

// DefaultItemBasedRateLimiter returns a new rate limiter with base delay of 5
// seconds, max delay of 5 minutes.
func DefaultItemBasedRateLimiter() workqueue.RateLimiter {
	return workqueue.NewItemExponentialFailureRateLimiter(time.Second*5, time.Minute*5)
}

// HandleOwnedResourceNamespacedFunc returns a function thataccepts a
// Kubernetes object and adds its owner references to the workqueue.
// https://kubernetes.io/docs/concepts/workloads/controllers/garbage-collection/#owners-and-dependents
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
					log.Error(err, "error getting referenced owning resource")
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

// QueuingEventHandler is an implementation of cache.ResourceEventHandler that
// simply queues objects that are added/updated/deleted.
type QueuingEventHandler struct {
	Queue workqueue.RateLimitingInterface
}

// Enqueue adds a key for an object to the workqueue.
func (q *QueuingEventHandler) Enqueue(obj interface{}) {
	key, err := KeyFunc(obj)
	if err != nil {
		runtime.HandleError(err)
		return
	}
	q.Queue.Add(key)
}

// OnAdd adds a newly created object to the workqueue.
func (q *QueuingEventHandler) OnAdd(obj interface{}) {
	q.Enqueue(obj)
}

// OnUpdate adds an updated object to the workqueue.
func (q *QueuingEventHandler) OnUpdate(old, new interface{}) {
	if reflect.DeepEqual(old, new) {
		return
	}
	q.Enqueue(new)
}

// OnDelete adds a deleted object to the workqueue for processing.
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

// Enqueue synchronously adds a key for an object to the workqueue.
func (b *BlockingEventHandler) Enqueue(obj interface{}) {
	b.WorkFunc(obj)
}

// OnAdd synchronously adds a newly created object to the workqueue.
func (b *BlockingEventHandler) OnAdd(obj interface{}) {
	b.WorkFunc(obj)
}

// OnUpdate synchronously adds an updated object to the workqueue.
func (b *BlockingEventHandler) OnUpdate(old, new interface{}) {
	if reflect.DeepEqual(old, new) {
		return
	}
	b.WorkFunc(new)
}

// OnDelete synchronously adds a deleted object to the workqueue.
func (b *BlockingEventHandler) OnDelete(obj interface{}) {
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = tombstone.Obj
	}
	b.WorkFunc(obj)
}

// BuildAnnotationsCopy takes a map of annotations and a list of prefix
// filters and builds a filtered map of annotations. It is used to filter
// annotations to be copied from Certificate to CertificateRequest and from
// CertificateSigningRequest to Order.
func BuildAnnotationsToCopy(allAnnotations map[string]string, prefixes []string) map[string]string {
	filteredAnnotations := make(map[string]string)
	includeAll := false
	for _, v := range prefixes {
		if v == "*" {
			includeAll = true
		}
	}
	for _, annotation := range prefixes {
		prefix := strings.TrimPrefix(annotation, "-")
		for k, v := range allAnnotations {
			if strings.HasPrefix(annotation, "-") {
				if strings.HasPrefix(k, prefix) {
					// If this is an annotation to not be copied.
					delete(filteredAnnotations, k)
				}
			} else if includeAll || strings.HasPrefix(k, annotation) {
				// If this is an annotation to be copied or if 'all' should be copied.
				filteredAnnotations[k] = v
			}
		}
	}
	return filteredAnnotations
}
