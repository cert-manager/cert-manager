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
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kclient "k8s.io/client-go/kubernetes"

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
		expectRequeueKey  types.NamespacedName
	}{
		{
			name: "ingress is re-queued when an 'Added' event is received for this ingress",
			givenCall: func(t *testing.T, _ cmclient.Interface, c kclient.Interface) {
				_, err := c.NetworkingV1().Ingresses("namespace-1").Create(context.Background(), &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "ingress-1",
				}}, metav1.CreateOptions{})
				require.NoError(t, err)
			},
			expectRequeueKey: types.NamespacedName{
				Namespace: "namespace-1",
				Name:      "ingress-1",
			},
		},
		{
			name: "ingress is re-queued when an 'Updated' event is received for this ingress",
			existingKObjects: []runtime.Object{&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
				Namespace: "namespace-1", Name: "ingress-1",
			}}},
			givenCall: func(t *testing.T, _ cmclient.Interface, c kclient.Interface) {
				_, err := c.NetworkingV1().Ingresses("namespace-1").Update(context.Background(), &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "ingress-1",
				}}, metav1.UpdateOptions{})
				require.NoError(t, err)
			},
			expectRequeueKey: types.NamespacedName{
				Namespace: "namespace-1",
				Name:      "ingress-1",
			},
		},
		{
			name: "ingress is re-queued when a 'Deleted' event is received for this ingress",
			existingKObjects: []runtime.Object{&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
				Namespace: "namespace-1", Name: "ingress-1",
			}}},
			givenCall: func(t *testing.T, _ cmclient.Interface, c kclient.Interface) {
				err := c.NetworkingV1().Ingresses("namespace-1").Delete(context.Background(), "ingress-1", metav1.DeleteOptions{})
				require.NoError(t, err)
			},
			expectRequeueKey: types.NamespacedName{
				Namespace: "namespace-1",
				Name:      "ingress-1",
			},
		},
		{
			name: "ingress is re-queued when an 'Added' event is received for its child Certificate",
			givenCall: func(t *testing.T, c cmclient.Interface, _ kclient.Interface) {
				_, err := c.CertmanagerV1().Certificates("namespace-1").Create(context.Background(), &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "cert-1",
					OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace-1", Name: "ingress-2",
					}}, ingressGVK)},
				}}, metav1.CreateOptions{})
				require.NoError(t, err)
			},
			expectRequeueKey: types.NamespacedName{
				Namespace: "namespace-1",
				Name:      "ingress-2",
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
				_, err := c.CertmanagerV1().Certificates("namespace-1").Update(context.Background(), &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "cert-1",
					OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace-1", Name: "ingress-2",
					}}, ingressGVK)},
				}}, metav1.UpdateOptions{})
				require.NoError(t, err)
			},
			expectRequeueKey: types.NamespacedName{
				Namespace: "namespace-1",
				Name:      "ingress-2",
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
				err := c.CertmanagerV1().Certificates("namespace-1").Delete(context.Background(), "cert-1", metav1.DeleteOptions{})
				require.NoError(t, err)
			},
			expectRequeueKey: types.NamespacedName{
				Namespace: "namespace-1",
				Name:      "ingress-2",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := &testpkg.Builder{T: t, CertManagerObjects: test.existingCMObjects, KubeObjects: test.existingKObjects}
			b.Init()

			// We don't care about the HasSynced functions since we already know
			// whether they have been properly "used": if no Gateway or
			// Certificate event is received then HasSynced has not been setup
			// properly.
			queue, _, err := (&controller{}).Register(b.Context)
			require.NoError(t, err)

			b.Start()
			defer b.Stop()

			test.givenCall(t, b.CMClient, b.Client)

			// We have no way of knowing when the informers will be done adding
			// items to the queue due to the "shared informer" architecture:
			// Start(stop) does not allow you to wait for the informers to be
			// done. To work around that, we do a second queue.Get and expect it
			// to be nil.
			time.AfterFunc(50*time.Millisecond, queue.ShutDown)

			var gotKeys []types.NamespacedName
			for {
				// Get blocks until either (1) a key is returned, or (2) the
				// queue is shut down.
				gotKey, done := queue.Get()
				if done {
					break
				}
				gotKeys = append(gotKeys, gotKey)
			}
			assert.Equal(t, 0, queue.Len(), "queue should be empty")

			// We only expect 0 or 1 keys received in the queue.
			if test.expectRequeueKey != (types.NamespacedName{}) {
				assert.Equal(t, []types.NamespacedName{test.expectRequeueKey}, gotKeys)
			} else {
				assert.Nil(t, gotKeys)
			}
		})
	}
}
