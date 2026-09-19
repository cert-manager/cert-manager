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
	"testing"
	"time"
	"sync"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/workqueue"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
)

var ingressGVK = networkingv1.SchemeGroupVersion.WithKind("Ingress")

func Test_controller_Register(t *testing.T) {
	tests := []struct {
		name              string
		existingKObjects  []runtime.Object
		existingCMObjects []runtime.Object
		givenCall         func(*testing.T, cmclient.Interface, kclient.Interface)
		expectAddCalls    []types.NamespacedName
	}{
		{
			name: "ingress is re-queued when an 'Added' event is received for this ingress",
			givenCall: func(t *testing.T, _ cmclient.Interface, c kclient.Interface) {
				_, err := c.NetworkingV1().Ingresses("namespace-1").Create(t.Context(), &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "ingress-1",
				}}, metav1.CreateOptions{})
				require.NoError(t, err)
			},
			expectAddCalls: []types.NamespacedName{
				{
					Namespace: "namespace-1",
					Name:      "ingress-1",
				},
			},
		},
		{
			name: "ingress is re-queued when an 'Updated' event is received for this ingress",
			existingKObjects: []runtime.Object{&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
				Namespace: "namespace-1", Name: "ingress-1",
			}}},
			givenCall: func(t *testing.T, _ cmclient.Interface, c kclient.Interface) {
				_, err := c.NetworkingV1().Ingresses("namespace-1").Update(t.Context(), &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "ingress-1",
				}}, metav1.UpdateOptions{})
				require.NoError(t, err)
			},
			expectAddCalls: []types.NamespacedName{
				{
					Namespace: "namespace-1",
					Name:      "ingress-1",
				},
			},
		},
		{
			name: "ingress is re-queued when a 'Deleted' event is received for this ingress",
			existingKObjects: []runtime.Object{&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
				Namespace: "namespace-1", Name: "ingress-1",
			}}},
			givenCall: func(t *testing.T, _ cmclient.Interface, c kclient.Interface) {
				err := c.NetworkingV1().Ingresses("namespace-1").Delete(t.Context(), "ingress-1", metav1.DeleteOptions{})
				require.NoError(t, err)
			},
			expectAddCalls: []types.NamespacedName{
				{
					Namespace: "namespace-1",
					Name:      "ingress-1",
				},
				{
					Namespace: "namespace-1",
					Name:      "ingress-1",
				},
			},
		},
		{
			name: "ingress is re-queued when an 'Added' event is received for its child Certificate",
			givenCall: func(t *testing.T, c cmclient.Interface, _ kclient.Interface) {
				_, err := c.CertmanagerV1().Certificates("namespace-1").Create(t.Context(), &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "cert-1",
					OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace-1", Name: "ingress-2",
					}}, ingressGVK)},
				}}, metav1.CreateOptions{})
				require.NoError(t, err)
			},
			expectAddCalls: []types.NamespacedName{
				{
					Namespace: "namespace-1",
					Name:      "ingress-2",
				},
			},
		},
		{
			name: "ingress is re-queued when an 'Updated' event is received for its child Certificate",
			existingCMObjects: []runtime.Object{&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{
				Namespace: "namespace-1", Name: "cert-1",
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "ingress-2",
					}}, ingressGVK)},
			}}},
			givenCall: func(t *testing.T, c cmclient.Interface, _ kclient.Interface) {
				_, err := c.CertmanagerV1().Certificates("namespace-1").Update(t.Context(), &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "cert-1",
					OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace-1", Name: "ingress-2",
					}}, ingressGVK)},
				}}, metav1.UpdateOptions{})
				require.NoError(t, err)
			},
			expectAddCalls: []types.NamespacedName{
				{
					Namespace: "namespace-1",
					Name:      "ingress-2",
				},
			},
		},
		{
			name: "ingress is re-queued when a 'Deleted' event is received for its child Certificate",
			existingCMObjects: []runtime.Object{&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{
				Namespace: "namespace-1", Name: "cert-1",
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "ingress-2",
				}}, ingressGVK)},
			}}},
			givenCall: func(t *testing.T, c cmclient.Interface, _ kclient.Interface) {
				err := c.CertmanagerV1().Certificates("namespace-1").Delete(t.Context(), "cert-1", metav1.DeleteOptions{})
				require.NoError(t, err)
			},
			expectAddCalls: []types.NamespacedName{
				{
					Namespace: "namespace-1",
					Name:      "ingress-2",
				},
				{
					Namespace: "namespace-1",
					Name:      "ingress-2",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := &testpkg.Builder{
				T:                  t,
				CertManagerObjects: test.existingCMObjects,
				KubeObjects:        test.existingKObjects,
			}
			b.Init()

			// We don't care about the HasSynced functions since we already know
			// whether they have been properly "used": if no Gateway or
			// Certificate event is received then HasSynced has not been setup
			// properly.
			mock := &mockWorkqueue{t: t}
			_, _, err := (&controller{queue: mock}).Register(b.Context)
			require.NoError(t, err)

			b.Start()
			defer b.Stop()

			test.givenCall(t, b.CMClient, b.Client)

			time.Sleep(50 * time.Millisecond)

			// We only expect 0 or 1 keys received in the queue, or 2 keys when
			// we have to create an Ingress before deleting or updating it.
			assert.Equal(t, test.expectAddCalls, mock.getCallsToAdd())
		})
	}
}

type mockWorkqueue struct {
	lock       sync.Mutex
	t          *testing.T
	callsToAdd []types.NamespacedName
}

var _ workqueue.TypedInterface[types.NamespacedName] = &mockWorkqueue{}

func (m *mockWorkqueue) Add(arg0 types.NamespacedName) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.callsToAdd = append(m.callsToAdd, arg0)
}

func (m *mockWorkqueue) getCallsToAdd() []types.NamespacedName {
	m.lock.Lock()
	defer m.lock.Unlock()
	return append([]types.NamespacedName(nil), m.callsToAdd...)
}

func (m *mockWorkqueue) AddAfter(arg0 types.NamespacedName, arg1 time.Duration) {
	m.t.Error("workqueue.AddAfter was called but was not expected to be called")
}

func (m *mockWorkqueue) AddRateLimited(arg0 types.NamespacedName) {
	m.t.Error("workqueue.AddRateLimited was called but was not expected to be called")
}

func (m *mockWorkqueue) Done(arg0 types.NamespacedName) {
	m.t.Error("workqueue.Done was called but was not expected to be called")
}

func (m *mockWorkqueue) Forget(arg0 types.NamespacedName) {
	m.t.Error("workqueue.Forget was called but was not expected to be called")
}

func (m *mockWorkqueue) Get() (types.NamespacedName, bool) {
	m.t.Error("workqueue.Get was called but was not expected to be called")
	return types.NamespacedName{}, false
}

func (m *mockWorkqueue) Len() int {
	m.t.Error("workqueue.Len was called but was not expected to be called")
	return 0
}

func (m *mockWorkqueue) NumRequeues(arg0 types.NamespacedName) int {
	m.t.Error("workqueue.NumRequeues was called but was not expected to be called")
	return 0
}

func (m *mockWorkqueue) ShutDown() {
	m.t.Error("workqueue.ShutDown was called but was not expected to be called")
}

func (m *mockWorkqueue) ShutDownWithDrain() {
	m.t.Error("workqueue.ShutDownWithDrain was called but was not expected to be called")

}

func (m *mockWorkqueue) ShuttingDown() bool {
	m.t.Error("workqueue.ShuttingDown was called but was not expected to be called")
	return false
}
