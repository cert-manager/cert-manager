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
	"reflect"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
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
) func(metav1.Object) {
	return func(metaobj metav1.Object) {
		log := log.WithName("handleOwnedResource")
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
	enqueue := func(obj metav1.Object) {
		queue.Add(cache.MetaObjectToName(obj).AsNamespacedName())
	}
	return filteredEventHandler[metav1.Object]{
		handler: handler.TypedFuncs[metav1.Object, types.NamespacedName]{
			CreateFunc: func(_ context.Context, e event.TypedCreateEvent[metav1.Object], _ workqueue.TypedRateLimitingInterface[types.NamespacedName]) {
				enqueue(e.Object)
			},
			UpdateFunc: func(_ context.Context, e event.TypedUpdateEvent[metav1.Object], _ workqueue.TypedRateLimitingInterface[types.NamespacedName]) {
				enqueue(e.ObjectNew)
			},
			DeleteFunc: func(_ context.Context, e event.TypedDeleteEvent[metav1.Object], _ workqueue.TypedRateLimitingInterface[types.NamespacedName]) {
				enqueue(e.Object)
			},
		},
		predicates: []predicate.TypedPredicate[metav1.Object]{
			onlyUpdateWhenResourceChanged[metav1.Object]{},
		},
	}
}

// BlockingEventHandler returns a cache.ResourceEventHandler that
// synchronously calls the workFunc upon calls to OnAdd, OnUpdate or
// OnDelete. It uses controller-runtime's handler.TypedFuncs internally
// and skips update events when the resource has not changed.
func BlockingEventHandler[T metav1.Object](
	workFunc func(obj T),
) cache.ResourceEventHandler {
	return filteredEventHandler[T]{
		handler: handler.TypedFuncs[T, types.NamespacedName]{
			CreateFunc: func(_ context.Context, e event.TypedCreateEvent[T], _ workqueue.TypedRateLimitingInterface[types.NamespacedName]) {
				workFunc(e.Object)
			},
			UpdateFunc: func(_ context.Context, e event.TypedUpdateEvent[T], _ workqueue.TypedRateLimitingInterface[types.NamespacedName]) {
				workFunc(e.ObjectNew)
			},
			DeleteFunc: func(_ context.Context, e event.TypedDeleteEvent[T], _ workqueue.TypedRateLimitingInterface[types.NamespacedName]) {
				workFunc(e.Object)
			},
		},
		predicates: []predicate.TypedPredicate[T]{
			onlyUpdateWhenResourceChanged[T]{},
		},
	}
}

// onlyUpdateWhenResourceChanged implements a predicate function only
// keeping update events when the resource version changed and falls
// back to deepequal compare when the resource version is missing.
//
// We need this predicate because otherwise we might unnecessarily
// reconcile resources when they did not actually change. Update events
// can be triggered for other reasons, e.g. periodic resyncs of informers.
// see https://github.com/kubernetes/client-go/blob/v0.34.3/tools/cache/controller.go#L227-L232
//
// This predicate is similar to the predicate in controller-runtime but with fallback
// see https://github.com/kubernetes-sigs/controller-runtime/blob/4b46eb04d57ff3bec4c3c05206c46af9aa647a24/pkg/predicate/predicate.go#L154
type onlyUpdateWhenResourceChanged[T metav1.Object] struct {
	predicate.TypedFuncs[T]
}

// Update implements default UpdateEvent filter for validating resource version change.
func (onlyUpdateWhenResourceChanged[T]) Update(e event.TypedUpdateEvent[T]) bool {
	if isNil(e.ObjectOld) {
		logf.Log.Error(nil, "Update event has no old object to update", "event", e)
		return false
	}
	if isNil(e.ObjectNew) {
		logf.Log.Error(nil, "Update event has no new object to update", "event", e)
		return false
	}

	// Fallback to DeepEqual when ResourceVersion is missing
	// this happens for example for our fake client tests.
	if e.ObjectNew.GetResourceVersion() == "" ||
		e.ObjectOld.GetResourceVersion() == "" {
		return !reflect.DeepEqual(e.ObjectOld, e.ObjectNew)
	}

	return e.ObjectNew.GetResourceVersion() != e.ObjectOld.GetResourceVersion()
}

// copied from https://github.com/kubernetes-sigs/controller-runtime/blob/5de4c4f5997c4b9469c7cfe003eff06bfdbd7f87/pkg/handler/enqueue.go#L110-L120
func isNil(arg any) bool {
	if v := reflect.ValueOf(arg); !v.IsValid() || ((v.Kind() == reflect.Pointer ||
		v.Kind() == reflect.Interface ||
		v.Kind() == reflect.Slice ||
		v.Kind() == reflect.Map ||
		v.Kind() == reflect.Chan ||
		v.Kind() == reflect.Func) && v.IsNil()) {
		return true
	}
	return false
}

// filteredEventHandler adapts a handler.TypedEventHandler to
// cache.ResourceEventHandler, applying predicates before forwarding typed
// events. This is the cert-manager equivalent of controller-runtime's
// internal.EventHandler — it bridges client-go informers to the typed
// handler interface.
type filteredEventHandler[T metav1.Object] struct {
	handler    handler.TypedEventHandler[T, types.NamespacedName]
	predicates []predicate.TypedPredicate[T]
}

var _ cache.ResourceEventHandler = filteredEventHandler[metav1.Object]{}

// FilterEventHandler returns a cache.ResourceEventHandler that applies the
// given predicates and delegates to the provided TypedEventHandler.
func FilterEventHandler[T metav1.Object](
	h handler.TypedEventHandler[T, types.NamespacedName],
	predicates ...predicate.TypedPredicate[T],
) cache.ResourceEventHandler {
	return filteredEventHandler[T]{
		handler:    h,
		predicates: predicates,
	}
}

func (q filteredEventHandler[T]) OnAdd(obj any, isInInitialList bool) {
	o, ok := obj.(T)
	if !ok {
		return
	}

	c := event.TypedCreateEvent[T]{Object: o, IsInInitialList: isInInitialList}
	for _, p := range q.predicates {
		if !p.Create(c) {
			return
		}
	}

	q.handler.Create(context.TODO(), c, nil)
}

func (q filteredEventHandler[T]) OnUpdate(oldObj, newObj any) {
	oOld, ok := oldObj.(T)
	if !ok {
		return
	}
	oNew, ok := newObj.(T)
	if !ok {
		return
	}

	u := event.TypedUpdateEvent[T]{ObjectOld: oOld, ObjectNew: oNew}
	for _, p := range q.predicates {
		if !p.Update(u) {
			return
		}
	}

	q.handler.Update(context.TODO(), u, nil)
}

func (q filteredEventHandler[T]) OnDelete(obj any) {
	d := event.TypedDeleteEvent[T]{}

	unwrappedObj := obj
	if tombstone, ok := unwrappedObj.(cache.DeletedFinalStateUnknown); ok {
		d.DeleteStateUnknown = true
		unwrappedObj = tombstone.Obj
	}

	o, ok := unwrappedObj.(T)
	if !ok {
		return
	}
	d.Object = o

	for _, p := range q.predicates {
		if !p.Delete(d) {
			return
		}
	}

	q.handler.Delete(context.TODO(), d, nil)
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

func ToSecret(obj metav1.Object) (*corev1.Secret, bool) {
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
