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

package metrics

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/metrics"
)

const (
	// ControllerName is the string used to refer to this controller
	// when enabling or disabling it from command line flags.
	ControllerName = "certificates-metrics"
)

// controllerWrapper wraps the `controller` structure to make it implement
// the controllerpkg.queueingController interface
type controllerWrapper struct {
	*controller
}

// This controller is synced on all Certificate 'create', 'update', and
// 'delete' events which will update the metrics for that Certificate.
type controller struct {
	certificateLister cmlisters.CertificateLister

	metrics *metrics.Metrics
}

func NewController(ctx *controllerpkg.Context) (*controller, workqueue.TypedRateLimitingInterface[types.NamespacedName], []cache.InformerSynced, error) {
	// create a queue used to queue up items to be processed
	queue := workqueue.NewTypedRateLimitingQueueWithConfig(
		controllerpkg.DefaultCertificateRateLimiter(),
		workqueue.TypedRateLimitingQueueConfig[types.NamespacedName]{
			Name: ControllerName,
		},
	)

	// obtain references to all the informers used by this controller
	certificateInformer := ctx.SharedInformerFactory.Certmanager().V1().Certificates()

	// Reconcile over all Certificate events. We do _not_ reconcile on Secret
	// events that are related to Certificates. It is the responsibility of the
	// Certificates controllers to update accordingly.
	if _, err := certificateInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: queue}); err != nil {
		return nil, nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}

	// build a list of InformerSynced functions that will be returned by the
	// Register method.  the controller will only begin processing items once all
	// of these informers have synced.
	mustSync := []cache.InformerSynced{
		certificateInformer.Informer().HasSynced,
	}

	return &controller{
		certificateLister: certificateInformer.Lister(),
		metrics:           ctx.Metrics,
	}, queue, mustSync, nil
}

func (c *controller) ProcessItem(ctx context.Context, key types.NamespacedName) error {
	namespace, name := key.Namespace, key.Name

	crt, err := c.certificateLister.Certificates(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		// If the Certificate no longer exists, remove its metrics from being exposed.
		c.metrics.RemoveCertificate(key)
		return nil
	}
	if err != nil {
		return err
	}

	// Update that Certificates metrics
	c.metrics.UpdateCertificate(crt)

	return nil
}

func (c *controllerWrapper) Register(ctx *controllerpkg.Context) (workqueue.TypedRateLimitingInterface[types.NamespacedName], []cache.InformerSynced, error) {
	ctrl, queue, mustSync, err := NewController(ctx)
	c.controller = ctrl
	return queue, mustSync, err
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&controllerWrapper{}).
			Complete()
	})
}
