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
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	"k8s.io/utils/clock"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/pkg/scheduler"
	"github.com/jetstack/cert-manager/pkg/util"
)

type Controller struct {
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

	return ctrl
}

func (c *Controller) Run(workers int, stopCh <-chan struct{}) error {
	klog.V(4).Infof("Starting %s control loop", ControllerName)
	// wait for all the informer caches we depend to sync
	if !cache.WaitForCacheSync(stopCh, c.syncedFuncs...) {
		return fmt.Errorf("error waiting for informer caches to sync")
	}

	klog.V(4).Infof("Synced all caches for %s control loop", ControllerName)

	for i := 0; i < workers; i++ {
		c.workerWg.Add(1)
		// TODO (@munnerz): make time.Second duration configurable
		go wait.Until(func() { c.worker(stopCh) }, time.Second, stopCh)
	}
	<-stopCh
	klog.V(4).Infof("Shutting down queue as workqueue signaled shutdown")
	c.queue.ShutDown()
	klog.V(4).Infof("Waiting for workers to exit...")
	c.workerWg.Wait()
	klog.V(4).Infof("Workers exited.")
	return nil
}

func (c *Controller) worker(stopCh <-chan struct{}) {
	defer c.workerWg.Done()
	klog.V(4).Infof("Starting %q worker", ControllerName)
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
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = util.ContextWithStopCh(ctx, stopCh)
			klog.Infof("%s controller: syncing item '%s'", ControllerName, key)
			if err := c.syncHandler(ctx, key); err != nil {
				klog.Errorf("%s controller: Re-queuing item %q due to error processing: %s", ControllerName, key, err.Error())
				c.queue.AddRateLimited(obj)
				return
			}
			klog.Infof("%s controller: Finished processing work item %q", ControllerName, key)
			c.queue.Forget(obj)
		}()
	}
	klog.V(4).Infof("Exiting %q worker loop", ControllerName)
}

func (c *Controller) processNextWorkItem(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	crt, err := c.certificateLister.Certificates(namespace).Get(name)

	if err != nil {
		if k8sErrors.IsNotFound(err) {
			c.scheduledWorkQueue.Forget(key)
			runtime.HandleError(fmt.Errorf("certificate '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	return c.Sync(ctx, crt)
}

var keyFunc = controllerpkg.KeyFunc

const (
	ControllerName = "certificates"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) controllerpkg.Interface {
		return New(ctx).Run
	})
}
