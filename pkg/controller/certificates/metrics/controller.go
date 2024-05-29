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
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

func NewController(ctx *controllerpkg.Context) (*controller, workqueue.RateLimitingInterface, []cache.InformerSynced) {
	// create a queue used to queue up items to be processed
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*1, time.Second*30), ControllerName)

	// obtain references to all the informers used by this controller
	certificateInformer := ctx.SharedInformerFactory.Certmanager().V1().Certificates()

	// Reconcile over all Certificate events. We do _not_ reconcile on Secret
	// events that are related to Certificates. It is the responsibility of the
	// Certificates controllers to update accordingly.
	certificateInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: queue})

	// build a list of InformerSynced functions that will be returned by the
	// Register method.  the controller will only begin processing items once all
	// of these informers have synced.
	mustSync := []cache.InformerSynced{
		certificateInformer.Informer().HasSynced,
	}

	return &controller{
		certificateLister: certificateInformer.Lister(),
		metrics:           ctx.Metrics,
	}, queue, mustSync
}

func (c *controller) ProcessItem(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil
	}

	crt, err := c.certificateLister.Certificates(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		// If the Certificate no longer exists, remove it's metrics from being exposed.
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

func (c *controllerWrapper) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	ctrl, queue, mustSync := NewController(ctx)
	c.controller = ctrl

	return queue, mustSync, nil
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&controllerWrapper{}).
			Complete()
	})
}
