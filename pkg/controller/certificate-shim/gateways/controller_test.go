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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
	gwclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
)

var gatewayGVK = gwapi.SchemeGroupVersion.WithKind("Gateway")

func Test_controller_Register(t *testing.T) {
	tests := []struct {
		name           string
		existingCert   *cmapi.Certificate
		givenCall      func(*testing.T, cmclient.Interface, gwclient.Interface)
		expectAddCalls []types.NamespacedName
	}{
		{
			name: "gateway is re-queued when an 'Added' event is received for this gateway",
			givenCall: func(t *testing.T, _ cmclient.Interface, c gwclient.Interface) {
				_, err := c.GatewayV1().Gateways("namespace-1").Create(context.Background(), &gwapi.Gateway{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "gateway-1",
				}}, metav1.CreateOptions{})
				require.NoError(t, err)
			},
			expectAddCalls: []types.NamespacedName{
				{
					Namespace: "namespace-1",
					Name:      "gateway-1",
				},
			},
		},
		{
			name: "gateway is re-queued when an 'Updated' event is received for this gateway",
			givenCall: func(t *testing.T, _ cmclient.Interface, c gwclient.Interface) {
				// We can't use the gateway-api fake.NewSimpleClientset due to
				// Gateway being pluralized as "gatewaies" instead of
				// "gateways". The trick is thus to use Create instead.
				_, err := c.GatewayV1().Gateways("namespace-1").Create(context.Background(), &gwapi.Gateway{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "gateway-1",
				}}, metav1.CreateOptions{})
				require.NoError(t, err)

				_, err = c.GatewayV1().Gateways("namespace-1").Update(context.Background(), &gwapi.Gateway{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "gateway-1", Labels: map[string]string{"foo": "bar"},
				}}, metav1.UpdateOptions{})
				require.NoError(t, err)
			},
			expectAddCalls: []types.NamespacedName{
				// Create
				{
					Namespace: "namespace-1",
					Name:      "gateway-1",
				},
				// Update
				{
					Namespace: "namespace-1",
					Name:      "gateway-1",
				},
			},
		},
		{
			name: "gateway is re-queued when a 'Deleted' event is received for this gateway",
			givenCall: func(t *testing.T, _ cmclient.Interface, c gwclient.Interface) {
				_, err := c.GatewayV1().Gateways("namespace-1").Create(context.Background(), &gwapi.Gateway{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "gateway-1",
				}}, metav1.CreateOptions{})
				require.NoError(t, err)

				err = c.GatewayV1().Gateways("namespace-1").Delete(context.Background(), "gateway-1", metav1.DeleteOptions{})
				require.NoError(t, err)
			},
			expectAddCalls: []types.NamespacedName{
				// Create
				{
					Namespace: "namespace-1",
					Name:      "gateway-1",
				},
				// Delete
				{
					Namespace: "namespace-1",
					Name:      "gateway-1",
				},
			},
		},
		{
			name: "gateway is re-queued when an 'Added' event is received for its child Certificate",
			givenCall: func(t *testing.T, c cmclient.Interface, _ gwclient.Interface) {
				_, err := c.CertmanagerV1().Certificates("namespace-1").Create(context.Background(), &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "cert-1",
					OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&gwapi.Gateway{ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace-1", Name: "gateway-2",
					}}, gatewayGVK)},
				}}, metav1.CreateOptions{})
				require.NoError(t, err)
			},
			expectAddCalls: []types.NamespacedName{
				{
					Namespace: "namespace-1",
					Name:      "gateway-2",
				},
			},
		},
		{
			name: "gateway is re-queued when an 'Updated' event is received for its child Certificate",
			existingCert: &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{
				Namespace: "namespace-1", Name: "cert-1",
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&gwapi.Gateway{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "gateway-2",
				}}, gatewayGVK)},
			}},
			givenCall: func(t *testing.T, c cmclient.Interface, _ gwclient.Interface) {
				_, err := c.CertmanagerV1().Certificates("namespace-1").Update(context.Background(), &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "cert-1",
					OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&gwapi.Gateway{ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace-1", Name: "gateway-2",
					}}, gatewayGVK)},
				}}, metav1.UpdateOptions{})
				require.NoError(t, err)
			},
			expectAddCalls: []types.NamespacedName{
				{
					Namespace: "namespace-1",
					Name:      "gateway-2",
				},
			},
		},
		{
			name: "gateway is re-queued when a 'Deleted' event is received for its child Certificate",
			existingCert: &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{
				Namespace: "namespace-1", Name: "cert-1",
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&gwapi.Gateway{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "gateway-2",
				}}, gatewayGVK)},
			}},
			givenCall: func(t *testing.T, c cmclient.Interface, _ gwclient.Interface) {
				// err := c.CertmanagerV1().Certificates("namespace-1").Delete(context.Background(), "cert-1", metav1.DeleteOptions{})
				// require.NoError(t, err)
			},
			expectAddCalls: []types.NamespacedName{
				{
					Namespace: "namespace-1",
					Name:      "gateway-2",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			var o []runtime.Object
			if test.existingCert != nil {
				o = append(o, test.existingCert)
			}

			// NOTE(mael): we can't use Gateway with GWObjects because of a
			// limitation in client-go's NewSimpleClientset. It uses a heuristic
			// that wrongly guesses the resource from the Gateway kind
			// ("gatewaies" instead of "gateways"). To work around this, the
			// only way is to either use a real apiserver or to use call Create
			// instead of setting existing objects with NewSimpleClientset. See:
			// https://github.com/kubernetes/client-go/blob/7a90b0858/testing/fixture.go#L326-L331
			b := &testpkg.Builder{T: t, CertManagerObjects: o}

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

			test.givenCall(t, b.CMClient, b.GWClient)

			// We have no way of knowing when the informers will be done adding
			// items to the queue due to the "shared informer" architecture:
			// Start(stop) does not allow you to wait for the informers to be
			// done.
			time.Sleep(50 * time.Millisecond)

			// We only expect 0 or 1 keys received in the queue, or 2 keys when
			// we have to create a Gateway before deleting or updating it.
			assert.Equal(t, test.expectAddCalls, mock.callsToAdd)
		})
	}
}

type mockWorkqueue struct {
	t          *testing.T
	callsToAdd []types.NamespacedName
}

var _ workqueue.TypedInterface[types.NamespacedName] = &mockWorkqueue{}

func (m *mockWorkqueue) Add(arg0 types.NamespacedName) {
	m.callsToAdd = append(m.callsToAdd, arg0)
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
