/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package certificates

import (
	"context"
	"fmt"
	"sync"
	"time"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/pkg/scheduler"
)

type Controller struct {
	// the controllers root context, containing a controller scoped logger
	ctx context.Context

	*controllerpkg.Context

	helper        issuer.Helper
	issuerFactory issuer.IssuerFactory

	// To allow injection for testing.
	syncHandler func(ctx context.Context, key string) error

	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
	certificateLister   cmlisters.CertificateLister
	secretLister        corelisters.SecretLister

	queue              workqueue.RateLimitingInterface
	scheduledWorkQueue scheduler.ScheduledWorkQueue
	workerWg           sync.WaitGroup
	syncedFuncs        []cache.InformerSynced
	metrics            *metrics.Metrics

	// used for testing
	clock clock.Clock

	// localTemporarySigner signs a certificate that is stored temporarily
	localTemporarySigner func(crt *v1alpha1.Certificate, pk []byte) ([]byte, error)
}

// New returns a new Certificates controller. It sets up the informer handler
// functions for all the types it watches.
func New(ctx *controllerpkg.Context) *Controller {
	ctrl := &Controller{Context: ctx}
	ctrl.syncHandler = ctrl.processNextWorkItem
	ctrl.queue = workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), "certificates")

	// Create a scheduled work queue that calls the ctrl.queue.Add method for
	// each object in the queue. This is used to schedule re-checks of
	// Certificate resources when they get near to expiry
	ctrl.scheduledWorkQueue = scheduler.NewScheduledWorkQueue(ctrl.queue.AddRateLimited)

	certificateInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().Certificates()
	certificateInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
	ctrl.certificateLister = certificateInformer.Lister()
	ctrl.syncedFuncs = append(ctrl.syncedFuncs, certificateInformer.Informer().HasSynced)

	issuerInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().Issuers()
	issuerInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: ctrl.handleGenericIssuer})
	ctrl.issuerLister = issuerInformer.Lister()
	ctrl.syncedFuncs = append(ctrl.syncedFuncs, issuerInformer.Informer().HasSynced)

	// if scoped to a single namespace
	if ctx.Namespace == "" {
		clusterIssuerInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers()
		clusterIssuerInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: ctrl.handleGenericIssuer})
		ctrl.clusterIssuerLister = clusterIssuerInformer.Lister()
		ctrl.syncedFuncs = append(ctrl.syncedFuncs, clusterIssuerInformer.Informer().HasSynced)
	}

	secretsInformer := ctrl.KubeSharedInformerFactory.Core().V1().Secrets()
	secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: ctrl.handleSecretResource})
	ctrl.secretLister = secretsInformer.Lister()
	ctrl.syncedFuncs = append(ctrl.syncedFuncs, secretsInformer.Informer().HasSynced)

	ordersInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().Orders()
	ordersInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: ctrl.handleOwnedResource})
	ctrl.syncedFuncs = append(ctrl.syncedFuncs, ordersInformer.Informer().HasSynced)

	ctrl.helper = issuer.NewHelper(ctrl.issuerLister, ctrl.clusterIssuerLister)
	ctrl.metrics = metrics.Default
	ctrl.helper = issuer.NewHelper(ctrl.issuerLister, ctrl.clusterIssuerLister)
	ctrl.issuerFactory = issuer.NewIssuerFactory(ctx)
	ctrl.clock = clock.RealClock{}
	ctrl.localTemporarySigner = generateLocallySignedTemporaryCertificate
	ctrl.ctx = logf.NewContext(ctx.RootContext, nil, ControllerName)

	return ctrl
}

func (c *Controller) Run(workers int, stopCh <-chan struct{}) error {
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	log := logf.FromContext(ctx)

	log.Info("starting control loop")
	// wait for all the informer caches we depend to sync
	if !cache.WaitForCacheSync(stopCh, c.syncedFuncs...) {
		return fmt.Errorf("error waiting for informer caches to sync")
	}

	log.Info("synced all caches for control loop")

	for i := 0; i < workers; i++ {
		c.workerWg.Add(1)
		// TODO (@munnerz): make time.Second duration configurable
		go wait.Until(func() { c.worker(ctx) }, time.Second, stopCh)
	}
	go wait.Until(func() { c.metrics.CleanUp(c.certificateLister) }, time.Minute, stopCh)
	<-stopCh
	log.V(logf.DebugLevel).Info("shutting down queue as workqueue signaled shutdown")
	c.queue.ShutDown()
	log.V(logf.DebugLevel).Info("waiting for workers to exit...")
	c.workerWg.Wait()
	log.V(logf.DebugLevel).Info("workers exited")
	return nil
}

func (c *Controller) worker(ctx context.Context) {
	log := logf.FromContext(ctx)
	defer c.workerWg.Done()
	log.V(logf.DebugLevel).Info("starting worker")
	for {
		obj, shutdown := c.queue.Get()
		if shutdown {
			break
		}

		var key string
		// use an inlined function so we can use defer
		func() {
			defer c.queue.Done(obj)
			var ok bool
			if key, ok = obj.(string); !ok {
				return
			}
			log := log.WithValues("key", key)
			log.Info("syncing resource")
			if err := c.syncHandler(ctx, key); err != nil {
				log.Error(err, "re-queuing item  due to error processing")
				c.queue.AddRateLimited(obj)
				return
			}
			log.Info("finished processing work item")
			c.queue.Forget(obj)
		}()
	}
	log.V(logf.DebugLevel).Info("exiting worker loop")
}

func (c *Controller) processNextWorkItem(ctx context.Context, key string) error {
	log := logf.FromContext(ctx)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "invalid resource key")
		return nil
	}

	crt, err := c.certificateLister.Certificates(namespace).Get(name)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			c.scheduledWorkQueue.Forget(key)
			log.Error(err, "certificate in work queue no longer exists")
			return nil
		}

		return err
	}

	ctx = logf.NewContext(ctx, logf.WithResource(log, crt))
	return c.Sync(ctx, crt)
}

var keyFunc = controllerpkg.KeyFunc

const (
	ControllerName = "certificates"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return New(ctx).Run, nil
	})
}
