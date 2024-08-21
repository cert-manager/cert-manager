/*
Copyright 2021 The cert-manager Authors.

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

package approver

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

const (
	ControllerName = "certificaterequests-approver"
)

// Controller is a CertificateRequest controller which manages the "Approved"
// condition. In the absence of any automated policy engine, this controller
// will _always_ set the "Approved" condition to True. All CertificateRequest
// signing controllers should wait until the "Approved" condition is set to
// True before processing.
type Controller struct {
	// logger to be used by this controller
	log logr.Logger

	certificateRequestLister cmlisters.CertificateRequestLister
	cmClient                 cmclient.Interface
	fieldManager             string

	recorder record.EventRecorder

	queue workqueue.TypedRateLimitingInterface[types.NamespacedName]
}

func init() {
	// create certificate request approver controller
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(new(Controller)).Complete()
	})
}

// Register registers and constructs the controller using the provided context.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
func (c *Controller) Register(ctx *controllerpkg.Context) (workqueue.TypedRateLimitingInterface[types.NamespacedName], []cache.InformerSynced, error) {
	c.log = logf.FromContext(ctx.RootContext, ControllerName)
	c.queue = workqueue.NewTypedRateLimitingQueueWithConfig(
		controllerpkg.DefaultItemBasedRateLimiter(),
		workqueue.TypedRateLimitingQueueConfig[types.NamespacedName]{
			Name: ControllerName,
		},
	)

	certificateRequestInformer := ctx.SharedInformerFactory.Certmanager().V1().CertificateRequests()
	mustSync := []cache.InformerSynced{certificateRequestInformer.Informer().HasSynced}
	if _, err := certificateRequestInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue}); err != nil {
		return nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}

	c.certificateRequestLister = certificateRequestInformer.Lister()
	c.cmClient = ctx.CMClient
	c.fieldManager = ctx.FieldManager
	c.recorder = ctx.Recorder

	c.log.V(logf.DebugLevel).Info("certificate request approver controller registered")

	return c.queue, mustSync, nil
}

func (c *Controller) ProcessItem(ctx context.Context, key types.NamespacedName) error {
	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

	namespace, name := key.Namespace, key.Name

	cr, err := c.certificateRequestLister.CertificateRequests(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		dbg.Info(fmt.Sprintf("certificate request in work queue no longer exists: %s", err))
		return nil
	}

	if err != nil {
		return err
	}

	ctx = logf.NewContext(ctx, logf.WithResource(log, cr))
	return c.Sync(ctx, cr)
}
