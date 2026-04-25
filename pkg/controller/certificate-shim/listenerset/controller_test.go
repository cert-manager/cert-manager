/*
Copyright 2026 The cert-manager Authors.

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

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
	gwclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gwapilisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	shimhelper "github.com/cert-manager/cert-manager/pkg/controller/certificate-shim"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
)

var listnerSetGVK = schema.GroupVersionKind{
	Group:   gwapi.GroupVersion.Group,
	Version: gwapi.GroupVersion.Version,
	Kind:    "ListenerSet",
}

func Test_controller_Register(t *testing.T) {
	tests := []struct {
		name           string
		existingCert   *cmapi.Certificate
		givenCall      func(*testing.T, cmclient.Interface, gwclient.Interface, gwapilisters.ListenerSetLister)
		expectAddCalls []types.NamespacedName
	}{
		{
			name: "listenerset is re-queued when an 'Added' event is received for this listenerset",
			givenCall: func(t *testing.T, _ cmclient.Interface, c gwclient.Interface, lsl gwapilisters.ListenerSetLister) {
				// Prefer Create calls for gateway-api fake clients; see Gateway test rationale.
				_, err := c.GatewayV1().ListenerSets("namespace-1").Create(t.Context(),
					&gwapi.ListenerSet{ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace-1", Name: "ls-1",
					}},
					metav1.CreateOptions{},
				)
				require.NoError(t, err)
			},
			expectAddCalls: []types.NamespacedName{{Namespace: "namespace-1", Name: "ls-1"}},
		},
		{
			name: "listenerset is re-queued when an 'Updated' event is received for this listenerset",
			givenCall: func(t *testing.T, _ cmclient.Interface, c gwclient.Interface, lsl gwapilisters.ListenerSetLister) {
				_, err := c.GatewayV1().ListenerSets("namespace-1").Create(t.Context(),
					&gwapi.ListenerSet{ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace-1", Name: "ls-1",
					}},
					metav1.CreateOptions{},
				)
				require.NoError(t, err)

				_, err = c.GatewayV1().ListenerSets("namespace-1").Update(t.Context(),
					&gwapi.ListenerSet{ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace-1", Name: "ls-1", Labels: map[string]string{"foo": "bar"},
					}},
					metav1.UpdateOptions{},
				)
				require.NoError(t, err)
			},
			expectAddCalls: []types.NamespacedName{
				// Create
				{Namespace: "namespace-1", Name: "ls-1"},
				// Update
				{Namespace: "namespace-1", Name: "ls-1"},
			},
		},
		{
			name: "listenerset is re-queued when a 'Deleted' event is received for this listenerset",
			givenCall: func(t *testing.T, _ cmclient.Interface, c gwclient.Interface, lsl gwapilisters.ListenerSetLister) {
				_, err := c.GatewayV1().ListenerSets("namespace-1").Create(t.Context(),
					&gwapi.ListenerSet{ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace-1", Name: "ls-1",
					}},
					metav1.CreateOptions{},
				)
				require.NoError(t, err)

				err = c.GatewayV1().ListenerSets("namespace-1").Delete(t.Context(), "ls-1", metav1.DeleteOptions{})
				require.NoError(t, err)
			},
			expectAddCalls: []types.NamespacedName{
				// Create
				{Namespace: "namespace-1", Name: "ls-1"},
				// Delete
				{Namespace: "namespace-1", Name: "ls-1"},
			},
		},
		{
			name: "listenerset is re-queued when its parent Gateway is updated (default issuer changes, etc.)",
			existingCert: &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{
				Namespace: "namespace-1", Name: "cert-1",
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&gwapi.ListenerSet{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "ls-3",
				}}, listnerSetGVK)},
			}},
			givenCall: func(t *testing.T, _ cmclient.Interface, c gwclient.Interface, lsl gwapilisters.ListenerSetLister) {
				// Create parent Gateway
				_, err := c.GatewayV1().Gateways("namespace-1").Create(t.Context(),
					&gwapi.Gateway{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "namespace-1", Name: "gw-1",
						},
						Spec: gwapi.GatewaySpec{
							AllowedListeners: &gwapi.AllowedListeners{
								Namespaces: &gwapi.ListenerNamespaces{
									From: func() *gwapi.FromNamespaces {
										s := gwapi.NamespacesFromSame
										return &s
									}(),
								},
							},
						},
					},
					metav1.CreateOptions{},
				)
				require.NoError(t, err)

				gwNS := gwapi.Namespace("namespace-1")
				// Create ListenerSet referencing that Gateway.
				_, err = c.GatewayV1().ListenerSets("namespace-1").Create(t.Context(),
					&gwapi.ListenerSet{
						ObjectMeta: metav1.ObjectMeta{Namespace: "namespace-1", Name: "ls-3"},
						Spec: gwapi.ListenerSetSpec{
							ParentRef: gwapi.ParentGatewayReference{
								Name: "gw-1",
								Kind: func() *gwapi.Kind {
									g := gwapi.Kind("Gateway")
									return &g
								}(),
								Namespace: &gwNS,
							},
						},
					},
					metav1.CreateOptions{},
				)
				require.NoError(t, err)

				require.Eventually(t, func() bool {
					_, err := lsl.ListenerSets("namespace-1").Get("ls-3")
					return err == nil
				}, 2*time.Second, 10*time.Millisecond)

				// Update Gateway -> should enqueue attached ls via the parent index.
				_, err = c.GatewayV1().Gateways("namespace-1").Update(t.Context(),
					&gwapi.Gateway{ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace-1", Name: "gw-1", Labels: map[string]string{"changed": "true"},
					}},
					metav1.UpdateOptions{},
				)
				require.NoError(t, err)
			},
			expectAddCalls: []types.NamespacedName{
				// Create ListenerSet (its own add handler)
				{Namespace: "namespace-1", Name: "ls-3"},
				// Gateway update triggers requeue of ls-3 via parent index
				{Namespace: "namespace-1", Name: "ls-3"},
				// Certificate create triggers requeue of ls-3 via parent index
				{Namespace: "namespace-1", Name: "ls-3"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var o []runtime.Object
			if test.existingCert != nil {
				o = append(o, test.existingCert)
			}

			// Build the controller test harness (same style as gateway controller tests).
			b := &testpkg.Builder{T: t, CertManagerObjects: o}
			b.Init()

			// We don't care about HasSynced correctness; if events enqueue keys, handlers were wired.
			mock := &mockWorkqueue{t: t}
			_, _, err := (&controller{queue: mock}).Register(b.Context)
			require.NoError(t, err)

			b.Start()
			defer b.Stop()

			test.givenCall(t, b.CMClient, b.GWClient, b.Context.GWShared.Gateway().V1().ListenerSets().Lister())

			require.Eventually(t, func() bool {
				require.Subsetf(t, test.expectAddCalls, mock.callsToAdd, "unexpected calls to workqueue.Add: got %v, want subset of %v", mock.callsToAdd, test.expectAddCalls)
				return true
			}, 2*time.Second, 10*time.Millisecond)
		})
	}
}

func Test_inheritAnnotations(t *testing.T) {
	var o []runtime.Object

	// Build the controller test harness (same style as gateway controller tests).
	b := &testpkg.Builder{T: t, CertManagerObjects: o}
	b.Init()

	// We don't care about HasSynced correctness; if events enqueue keys, handlers were wired.
	mock := &mockWorkqueue{t: t}
	_, _, err := (&controller{queue: mock}).Register(b.Context)
	require.NoError(t, err)

	b.Start()
	defer b.Stop()

	gw, err := b.GWClient.GatewayV1().Gateways("namespace-1").Create(t.Context(),
		&gwapi.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "namespace-1",
				Name:      "gw-1",
				Annotations: map[string]string{
					"cert-manager.io/issuer":       "test-issuer",
					"cert-manager.io/issuer-kind":  "ClusterIssuer",
					"cert-manager.io/issuer-group": "cert-manager.io",
				},
			},
			Spec: gwapi.GatewaySpec{
				AllowedListeners: &gwapi.AllowedListeners{
					Namespaces: &gwapi.ListenerNamespaces{
						From: func() *gwapi.FromNamespaces {
							s := gwapi.NamespacesFromSame
							return &s
						}(),
					},
				},
			},
		},
		metav1.CreateOptions{},
	)
	require.NoError(t, err)

	gwNS := gwapi.Namespace("namespace-1")
	// Create ListenerSet referencing that Gateway.
	ls, err := b.GWClient.GatewayV1().ListenerSets("namespace-1").Create(t.Context(),
		&gwapi.ListenerSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "namespace-1",
				Name:      "ls-4",
				Annotations: map[string]string{
					"cert-manager.io/issuer":       "test-issuer-1",
					"cert-manager.io/issuer-group": "cert-manager.io",
				},
			},
			Spec: gwapi.ListenerSetSpec{
				ParentRef: gwapi.ParentGatewayReference{
					Name: "gw-1",
					Kind: func() *gwapi.Kind {
						g := gwapi.Kind("Gateway")
						return &g
					}(),
					Namespace: &gwNS,
				},
			},
		},
		metav1.CreateOptions{},
	)
	require.NoError(t, err)

	// Shared informer async: allow time for handlers to enqueue.
	time.Sleep(50 * time.Millisecond)
	inheritAnnotations(ls, gw)

	require.Equal(t, "test-issuer-1", ls.GetAnnotations()["cert-manager.io/issuer"])
	require.Equal(t, "ClusterIssuer", ls.GetAnnotations()["cert-manager.io/issuer-kind"])
}

func Test_setHTTP01ParentRef(t *testing.T) {
	httpsProtocol := gwapi.HTTPSProtocolType
	httpProtocol := gwapi.HTTPProtocolType

	tests := []struct {
		name                 string
		listenerSetListeners []gwapi.ListenerEntry
		gatewayListeners     []gwapi.Listener
		gatewayName          string
		gatewayNamespace     string
		listenerSetName      string
		listenerSetNamespace string
		expectKind           string
		expectName           string
		expectNamespace      string
		expectNoAnnotations  bool
	}{
		{
			name:                 "HTTP listener on ListenerSet — solver points to ListenerSet",
			listenerSetName:      "my-ls",
			listenerSetNamespace: "app",
			gatewayName:          "gateway",
			gatewayNamespace:     "infra",
			listenerSetListeners: []gwapi.ListenerEntry{
				{Protocol: httpsProtocol},
				{Protocol: httpProtocol},
			},
			gatewayListeners: []gwapi.Listener{
				{Protocol: httpsProtocol},
			},
			expectKind:      "ListenerSet",
			expectName:      "my-ls",
			expectNamespace: "",
		},
		{
			name:                 "HTTP listener on Gateway only — solver falls back to Gateway with correct namespace",
			listenerSetName:      "my-ls",
			listenerSetNamespace: "app",
			gatewayName:          "gateway",
			gatewayNamespace:     "infra",
			listenerSetListeners: []gwapi.ListenerEntry{
				{Protocol: httpsProtocol},
			},
			gatewayListeners: []gwapi.Listener{
				{Protocol: httpProtocol},
				{Protocol: httpsProtocol},
			},
			expectKind:      "Gateway",
			expectName:      "gateway",
			expectNamespace: "infra",
		},
		{
			name:                 "No HTTP listener on either — no annotations set, falls back to existing behavior",
			listenerSetName:      "my-ls",
			listenerSetNamespace: "app",
			gatewayName:          "gateway",
			gatewayNamespace:     "infra",
			listenerSetListeners: []gwapi.ListenerEntry{
				{Protocol: httpsProtocol},
			},
			gatewayListeners: []gwapi.Listener{
				{Protocol: httpsProtocol},
			},
			expectNoAnnotations: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listenerSet := &gwapi.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      tt.listenerSetName,
					Namespace: tt.listenerSetNamespace,
				},
				Spec: gwapi.ListenerSetSpec{
					Listeners: tt.listenerSetListeners,
				},
			}
			gateway := &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      tt.gatewayName,
					Namespace: tt.gatewayNamespace,
				},
				Spec: gwapi.GatewaySpec{
					Listeners: tt.gatewayListeners,
				},
			}

			setHTTP01ParentRef(listenerSet, gateway)
			listenerSetAnnotations := listenerSet.GetAnnotations()

			if tt.expectNoAnnotations {
				require.NotContains(t, listenerSetAnnotations,
					shimhelper.InternalHTTP01ParentRefKind)
				require.NotContains(t, listenerSetAnnotations,
					shimhelper.InternalHTTP01ParentRefName)
				require.NotContains(t, listenerSetAnnotations,
					shimhelper.InternalHTTP01ParentRefNamespace)
				return
			}

			require.Equal(t, tt.expectKind,
				listenerSetAnnotations[shimhelper.InternalHTTP01ParentRefKind])
			require.Equal(t, tt.expectName,
				listenerSetAnnotations[shimhelper.InternalHTTP01ParentRefName])

			if tt.expectNamespace == "" {
				require.NotContains(t, listenerSetAnnotations,
					shimhelper.InternalHTTP01ParentRefNamespace)
			} else {
				require.Equal(t, tt.expectNamespace,
					listenerSetAnnotations[shimhelper.InternalHTTP01ParentRefNamespace])
			}
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
