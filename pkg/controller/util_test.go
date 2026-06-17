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
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func TestBuildAnnotationsToCopy(t *testing.T) {
	tests := map[string]struct {
		allAnnotations map[string]string
		prefixes       []string
		want           map[string]string
	}{
		"no annotations should be copied": {
			allAnnotations: map[string]string{"foo": "bar", "bar": "bat"},
			prefixes:       []string{},
			want:           make(map[string]string),
		},
		"all annotations should be copied": {
			allAnnotations: map[string]string{"foo": "bar", "bar": "bat"},
			prefixes:       []string{"*"},
			want:           map[string]string{"foo": "bar", "bar": "bat"},
		},
		"all except some should be copied": {
			allAnnotations: map[string]string{"foo": "bar", "foo.io/thing": "bar", "foo.io/anotherthing": "bat", "bar": "bat"},
			prefixes:       []string{"*", "-foo.io/"},
			want:           map[string]string{"foo": "bar", "bar": "bat"},
		},
		"only some should be copied": {
			allAnnotations: map[string]string{
				"foo": "bar", "foo.io/thing": "bar", "foo.io/anotherthing": "bat", "bar": "bat",
			},
			prefixes: []string{"foo.io/"},
			want:     map[string]string{"foo.io/thing": "bar", "foo.io/anotherthing": "bat"},
		},
		"some annotations have been specified, but none found on the cert": {
			allAnnotations: map[string]string{},
			prefixes:       []string{"*", "-foo.io/"},
			want:           map[string]string{},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := BuildAnnotationsToCopy(test.allAnnotations, test.prefixes); !reflect.DeepEqual(got, test.want) {
				t.Errorf("BuildAnnotationsToCopy() = %+#v, want %+#v", got, test.want)
			}
		})
	}
}

func TestOnlyUpdateWhenResourceChanged(t *testing.T) {
	tests := map[string]struct {
		oldObj *corev1.ConfigMap
		newObj *corev1.ConfigMap
		want   bool
	}{
		"different resource versions considered changed": {
			oldObj: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "obj", Namespace: "ns", ResourceVersion: "1"}},
			newObj: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "obj", Namespace: "ns", ResourceVersion: "2"}},
			want:   true,
		},
		"same resource versions considered unchanged": {
			oldObj: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "obj", Namespace: "ns", ResourceVersion: "1"}, Data: map[string]string{"a": "b"}},
			// WARNING: this tests that we only compare the resource versions, not the full object.
			// A real API server would never return two different objects with the same resource version.
			newObj: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "obj", Namespace: "ns", ResourceVersion: "1"}, Data: map[string]string{"a": "c"}},
			want:   false,
		},
		"empty resource versions fallback to DeepEqual - equal objects": {
			oldObj: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "obj", Namespace: "ns"}, Data: map[string]string{"a": "b"}},
			newObj: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "obj", Namespace: "ns"}, Data: map[string]string{"a": "b"}},
			want:   false,
		},
		"empty resource versions fallback to DeepEqual - different objects": {
			oldObj: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "obj", Namespace: "ns"}, Data: map[string]string{"a": "b"}},
			newObj: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "obj", Namespace: "ns"}, Data: map[string]string{"a": "c"}},
			want:   true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			predicate := onlyUpdateWhenResourceChanged[metav1.Object]{}
			e := event.TypedUpdateEvent[metav1.Object]{
				ObjectOld: tt.oldObj,
				ObjectNew: tt.newObj,
			}
			got := predicate.Update(e)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestBlockingEventHandler(t *testing.T) {
	obj1 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "obj-name", Namespace: "obj-namespace", Annotations: map[string]string{"test": "test-1"}},
	}
	obj2 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "obj-name", Namespace: "obj-namespace", Annotations: map[string]string{"test": "test-2"}},
	}
	tests := map[string]struct {
		triggerEvent func(handler cache.ResourceEventHandler)
		expectCalls  int
	}{
		"OnAdd should call workFunc once": {
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnAdd(obj1, false)
			},
			expectCalls: 1,
		},
		"OnUpdate should call workFunc once when objects differ": {
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnUpdate(obj2, obj1)
			},
			expectCalls: 1,
		},
		"OnUpdate should not call workFunc when objects are the same": {
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnUpdate(obj1, obj1)
			},
			expectCalls: 0,
		},
		"OnDelete should call workFunc once": {
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnDelete(obj1)
			},
			expectCalls: 1,
		},
		"OnDelete with tombstone should call workFunc once": {
			triggerEvent: func(handler cache.ResourceEventHandler) {
				tombstone := cache.DeletedFinalStateUnknown{Key: "default/test-cm", Obj: obj1}
				handler.OnDelete(tombstone)
			},
			expectCalls: 1,
		},
		"OnUpdate with nil new object should not panic": {
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnUpdate(obj1, nil)
			},
			expectCalls: 0,
		},
		"OnAdd with non-metav1.Object value should not panic": {
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnAdd("test", true)
			},
			expectCalls: 0,
		},
		"OnDelete with non-metav1.Object value should not panic": {
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnDelete("test")
			},
			expectCalls: 0,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			callCount := 0
			handler := BlockingEventHandler(func(obj metav1.Object) {
				require.Equal(t, obj, obj1)
				callCount++
			})

			test.triggerEvent(handler)

			if callCount != test.expectCalls {
				t.Errorf("expected workFunc to be called %d times, got %d", test.expectCalls, callCount)
			}
		})
	}
}

func TestQueuingEventHandler(t *testing.T) {
	obj1 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "obj-name", Namespace: "obj-namespace", Annotations: map[string]string{"test": "test-1"}},
	}
	obj2 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "obj-name", Namespace: "obj-namespace", Annotations: map[string]string{"test": "test-2"}},
	}
	tests := map[string]struct {
		triggerEvent func(handler cache.ResourceEventHandler)
		expectItems  int
	}{
		"OnAdd should queue the object": {
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnAdd(obj1, false)
			},
			expectItems: 1,
		},
		"OnUpdate should queue when objects differ": {
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnUpdate(obj2, obj1)
			},
			expectItems: 1,
		},
		"OnUpdate should not queue when objects are identical": {
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnUpdate(obj1, obj1)
			},
			expectItems: 0,
		},
		"OnDelete should queue the object": {
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnDelete(obj1)
			},
			expectItems: 1,
		},
		"OnDelete with tombstone should queue the object": {
			triggerEvent: func(handler cache.ResourceEventHandler) {
				tombstone := cache.DeletedFinalStateUnknown{Key: "default/test-cm", Obj: obj1}
				handler.OnDelete(tombstone)
			},
			expectItems: 1,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			queue := workqueue.NewTypedRateLimitingQueue(DefaultItemBasedRateLimiter())
			defer queue.ShutDown()

			handler := QueuingEventHandler(queue)
			test.triggerEvent(handler)

			if queueLen := queue.Len(); queueLen != test.expectItems {
				t.Errorf("expected queue to have %d items, got %d", test.expectItems, queueLen)
			}

			if test.expectItems > 0 {
				item, _ := queue.Get()
				expected := types.NamespacedName{Name: "obj-name", Namespace: "obj-namespace"}
				if item != expected {
					t.Errorf("expected queue item to be %v, got %v", expected, item)
				}
			}
		})
	}
}

func TestFilterEventHandler(t *testing.T) {
	obj1 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "obj-name", Namespace: "obj-namespace", Annotations: map[string]string{"test": "test-1"}},
	}
	obj2 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "obj-name", Namespace: "obj-namespace", Annotations: map[string]string{"test": "test-2"}},
	}
	tests := map[string]struct {
		predicate    predicate.TypedPredicate[metav1.Object]
		triggerEvent func(handler cache.ResourceEventHandler)
		expectCalls  int
	}{
		"OnAdd should call handler when predicate returns true": {
			predicate: predicate.NewTypedPredicateFuncs(func(obj metav1.Object) bool {
				require.Equal(t, obj, obj1)
				return true
			}),
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnAdd(obj1, false)
			},
			expectCalls: 1,
		},
		"OnAdd should not call handler when predicate returns false": {
			predicate: predicate.NewTypedPredicateFuncs(func(obj metav1.Object) bool {
				require.Equal(t, obj, obj1)
				return false
			}),
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnAdd(obj1, false)
			},
			expectCalls: 0,
		},
		"OnUpdate should call handler when predicate returns true": {
			predicate: predicate.NewTypedPredicateFuncs(func(obj metav1.Object) bool {
				require.Equal(t, obj, obj2)
				return true
			}),
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnUpdate(obj1, obj2)
			},
			expectCalls: 1,
		},
		"OnUpdate should not call handler when predicate returns false": {
			predicate: predicate.NewTypedPredicateFuncs(func(obj metav1.Object) bool {
				require.Equal(t, obj, obj2)
				return false
			}),
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnUpdate(obj1, obj2)
			},
			expectCalls: 0,
		},
		"OnDelete should call handler when predicate returns true": {
			predicate: predicate.NewTypedPredicateFuncs(func(obj metav1.Object) bool {
				require.Equal(t, obj, obj1)
				return true
			}),
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnDelete(obj1)
			},
			expectCalls: 1,
		},
		"OnDelete should not call handler when predicate returns false": {
			predicate: predicate.NewTypedPredicateFuncs(func(obj metav1.Object) bool {
				require.Equal(t, obj, obj1)
				return false
			}),
			triggerEvent: func(handler cache.ResourceEventHandler) {
				handler.OnDelete(obj1)
			},
			expectCalls: 0,
		},
		"OnDelete with tombstone and predicate true": {
			predicate: predicate.NewTypedPredicateFuncs(func(obj metav1.Object) bool {
				require.Equal(t, obj, obj1)
				return true
			}),
			triggerEvent: func(handler cache.ResourceEventHandler) {
				tombstone := cache.DeletedFinalStateUnknown{Key: "default/test-cm", Obj: obj1}
				handler.OnDelete(tombstone)
			},
			expectCalls: 1,
		},
		"OnDelete with tombstone and predicate false": {
			predicate: predicate.NewTypedPredicateFuncs(func(obj metav1.Object) bool {
				require.Equal(t, obj, obj1)
				return false
			}),
			triggerEvent: func(handler cache.ResourceEventHandler) {
				tombstone := cache.DeletedFinalStateUnknown{Key: "default/test-cm", Obj: obj1}
				handler.OnDelete(tombstone)
			},
			expectCalls: 0,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			callCount := 0
			handler := FilterEventHandler(
				BlockingEventHandler(func(obj metav1.Object) { callCount++ }),
				test.predicate,
			)

			test.triggerEvent(handler)

			if callCount != test.expectCalls {
				t.Errorf("expected handler to be called %d times, got %d", test.expectCalls, callCount)
			}
		})
	}
}
