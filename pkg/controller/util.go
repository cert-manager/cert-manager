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
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// DefaultItemBasedRateLimiter returns a new rate limiter with base delay of 5
// seconds, max delay of 5 minutes.
func DefaultItemBasedRateLimiter() workqueue.TypedRateLimiter[types.NamespacedName] {
	return workqueue.NewTypedItemExponentialFailureRateLimiter[types.NamespacedName](time.Second*5, time.Minute*5)
}

// DefaultCertificateRateLimiter returns a new rate limiter with base delay of 1
// seconds, max delay of 30 seconds.
func DefaultCertificateRateLimiter() workqueue.TypedRateLimiter[types.NamespacedName] {
	return workqueue.NewTypedItemExponentialFailureRateLimiter[types.NamespacedName](time.Second*1, time.Second*30)
}

// DefaultACMERateLimiter returns a new rate limiter with base delay of 5
// seconds, max delay of 30 minutes.
func DefaultACMERateLimiter() workqueue.TypedRateLimiter[types.NamespacedName] {
	return workqueue.NewTypedItemExponentialFailureRateLimiter[types.NamespacedName](time.Second*5, time.Minute*30)
}

// HandleOwnedResourceNamespacedFunc returns a function that accepts a
// Kubernetes object and adds its owner references to the workqueue.
// https://kubernetes.io/docs/concepts/workloads/controllers/garbage-collection/#owners-and-dependents
func HandleOwnedResourceNamespacedFunc[T metav1.Object](
	log logr.Logger,
	queue workqueue.TypedRateLimitingInterface[types.NamespacedName],
	ownerGVK schema.GroupVersionKind,
	get func(namespace, name string) (T, error),
) func(obj interface{}) {
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
				obj, err := get(metaobj.GetNamespace(), ref.Name)
				// This function is always called with a getter
				// that gets from informers cache. Because this
				// is also called on cache sync it may be that
				// the owner is not yet in the cache.
				if err != nil && errors.IsNotFound(err) {
					log.Info("owning resource not found in cache")
					continue
				}
				if err != nil {
					log.Error(err, "error getting referenced owning resource from cache")
					continue
				}
				queue.Add(types.NamespacedName{
					Name:      obj.GetName(),
					Namespace: obj.GetNamespace(),
				})
			}
		}
	}
}

// QueuingEventHandler returns a cache.ResourceEventHandler that
// simply queues objects that are added/updated/deleted. It skips
// update events in case the resource has not changed.
func QueuingEventHandler(
	queue workqueue.TypedRateLimitingInterface[types.NamespacedName],
) cache.ResourceEventHandler {
	return filteredEventHandler{
		handler: blockingEventHandler{workFunc: func(obj interface{}) {
			objectName, err := cache.ObjectToName(obj)
			if err != nil {
				runtime.HandleError(err)
				return
			}
			queue.Add(types.NamespacedName{
				Name:      objectName.Name,
				Namespace: objectName.Namespace,
			})
		}},
		predicates: []predicate.TypedPredicate[metav1.Object]{
			// prevent unnecessary reconciliations in case the resource did not update
			onlyUpdateWhenResourceChanged{},
		},
	}
}

// blockingEventHandler is an implementation of cache.ResourceEventHandler that
// simply synchronously calls its workFunc upon calls to OnAdd, OnUpdate or
// OnDelete.
// It skips update events in case the resource has not changed.
type blockingEventHandler struct {
	workFunc func(obj interface{})
}

var _ cache.ResourceEventHandler = blockingEventHandler{}

// BlockingEventHandler returns a cache.ResourceEventHandler that
// simply synchronously calls the workFunc upon calls to OnAdd, OnUpdate or
// OnDelete. It skips update events in case the resource has not changed.
func BlockingEventHandler(
	workFunc func(obj any),
) cache.ResourceEventHandler {
	return filteredEventHandler{
		handler: blockingEventHandler{workFunc: workFunc},
		predicates: []predicate.TypedPredicate[metav1.Object]{
			// prevent unnecessary reconciliations in case the resource did not update
			onlyUpdateWhenResourceChanged{},
		},
	}
}

// OnAdd synchronously adds a newly created object to the workqueue.
func (b blockingEventHandler) OnAdd(obj interface{}, isInInitialList bool) {
	b.workFunc(obj)
}

// OnUpdate synchronously adds an updated object to the workqueue.
func (b blockingEventHandler) OnUpdate(oldObj, newObj interface{}) {
	b.workFunc(newObj)
}

// OnDelete synchronously adds a deleted object to the workqueue.
func (b blockingEventHandler) OnDelete(obj interface{}) {
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = tombstone.Obj
	}
	b.workFunc(obj)
}

// onlyUpdateWhenResourceChanged implements a predicate function only
// keeping update events when the resources does not deepequal
type onlyUpdateWhenResourceChanged struct {
	predicate.TypedFuncs[metav1.Object]
}

// Update implements default UpdateEvent filter for validating resource version change.
func (onlyUpdateWhenResourceChanged) Update(e event.TypedUpdateEvent[metav1.Object]) bool {
	if e.ObjectOld == nil {
		logf.Log.Error(nil, "Update event has no old object to update", "event", e)
		return false
	}
	if e.ObjectNew == nil {
		logf.Log.Error(nil, "Update event has no new object to update", "event", e)
		return false
	}

	return !reflect.DeepEqual(e.ObjectOld, e.ObjectNew)
}

// filteredEventHandler is an implementation of cache.ResourceEventHandler that
// only passes the event to the handler when all predicates return true
type filteredEventHandler struct {
	handler cache.ResourceEventHandler
	// predicates is a list of predicates that must all pass
	// for the object to be enqueued.
	predicates []predicate.TypedPredicate[metav1.Object]
}

var _ cache.ResourceEventHandler = filteredEventHandler{}

// FilterEventHandler returns a cache.ResourceEventHandler that
// skips events based on the passed predicates and passes all other
// events to the provided handler.
func FilterEventHandler(
	handler cache.ResourceEventHandler,
	predicates ...predicate.TypedPredicate[metav1.Object],
) cache.ResourceEventHandler {
	return filteredEventHandler{
		handler:    handler,
		predicates: predicates,
	}
}

// OnAdd adds a newly created object to the workqueue.
func (q filteredEventHandler) OnAdd(obj interface{}, isInInitialList bool) {
	log := logf.Log.WithName("filteredEventHandler").WithValues("event", "OnAdd")

	c := event.TypedCreateEvent[metav1.Object]{
		IsInInitialList: isInInitialList,
	}

	// Pull Object out of the object
	if o, ok := obj.(metav1.Object); ok {
		c.Object = o
	} else {
		log.Error(nil, "OnAdd missing Object", "object", obj, "type", fmt.Sprintf("%T", obj))
		return
	}

	for _, p := range q.predicates {
		if !p.Create(c) {
			return
		}
	}

	q.handler.OnAdd(obj, isInInitialList)
}

// OnUpdate adds an updated object to the workqueue.
func (q filteredEventHandler) OnUpdate(oldObj, newObj interface{}) {
	log := logf.Log.WithName("filteredEventHandler").WithValues("event", "OnUpdate")

	u := event.TypedUpdateEvent[metav1.Object]{}

	if o, ok := oldObj.(metav1.Object); ok {
		u.ObjectOld = o
	} else {
		log.Error(nil, "OnUpdate missing ObjectOld", "object", oldObj, "type", fmt.Sprintf("%T", oldObj))
		return
	}

	// Pull Object out of the object
	if o, ok := newObj.(metav1.Object); ok {
		u.ObjectNew = o
	} else {
		log.Error(nil, "OnUpdate missing ObjectNew", "object", newObj, "type", fmt.Sprintf("%T", newObj))
		return
	}

	for _, p := range q.predicates {
		if !p.Update(u) {
			return
		}
	}

	q.handler.OnUpdate(oldObj, newObj)
}

// OnDelete adds a deleted object to the workqueue for processing.
func (q filteredEventHandler) OnDelete(obj interface{}) {
	log := logf.Log.WithName("filteredEventHandler").WithValues("event", "OnDelete")

	d := event.TypedDeleteEvent[metav1.Object]{}

	unwrappedObj := obj

	// If the object doesn't have Metadata, assume it is a tombstone object of type DeletedFinalStateUnknown
	tombstone, ok := unwrappedObj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Set DeleteStateUnknown to true
		d.DeleteStateUnknown = true

		unwrappedObj = tombstone.Obj
	}

	// Pull Object out of the object
	if o, ok := unwrappedObj.(metav1.Object); ok {
		d.Object = o
	} else {
		log.Error(nil, "OnDelete missing Object", "object", unwrappedObj, "type", fmt.Sprintf("%T", unwrappedObj))
		return
	}

	for _, p := range q.predicates {
		if !p.Delete(d) {
			return
		}
	}

	q.handler.OnDelete(obj)
}

// BuildAnnotationsToCopy takes a map of annotations and a list of prefix
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

func ToSecret(obj interface{}) (*corev1.Secret, bool) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		meta, ok := obj.(*metav1.PartialObjectMetadata)
		if !ok {
			// TODO: I wasn't able to get GVK from PartialMetadata,
			// however perhaps this should be possible and then we
			// could verify that this really is a Secret. At the
			// moment this is okay as there is no path how any
			// reconcile loop would receive PartialObjectMetadata
			// for any other type.
			return nil, false
		}
		secret = &corev1.Secret{}
		secret.SetName(meta.Name)
		secret.SetNamespace(meta.Namespace)
	}
	return secret, true
}
