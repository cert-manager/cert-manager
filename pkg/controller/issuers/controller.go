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

package issuers

import (
	"context"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
)

type Controller struct {
	// the controllers root context, containing a controller scoped logger
	ctx context.Context
	*controllerpkg.Context
	issuerFactory issuer.IssuerFactory

	// To allow injection for testing.
	syncHandler func(ctx context.Context, key string) error

	issuerLister cmlisters.IssuerLister
	secretLister corelisters.SecretLister

	watchedInformers []cache.InformerSynced
	queue            workqueue.RateLimitingInterface
	metrics          *metrics.Metrics
}

func New(ctx *controllerpkg.Context) *Controller {
	ctrl := &Controller{
		Context: ctx,
	}

	ctrl.syncHandler = ctrl.processNextWorkItem
	ctrl.queue = workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), "issuers")

	issuerInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().Issuers()
	issuerInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
	ctrl.watchedInformers = append(ctrl.watchedInformers, issuerInformer.Informer().HasSynced)
	ctrl.issuerLister = issuerInformer.Lister()

	secretsInformer := ctrl.KubeSharedInformerFactory.Core().V1().Secrets()
	secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: ctrl.secretDeleted})
	ctrl.watchedInformers = append(ctrl.watchedInformers, secretsInformer.Informer().HasSynced)
	ctrl.secretLister = secretsInformer.Lister()
	ctrl.issuerFactory = issuer.NewIssuerFactory(ctx)
	ctrl.ctx = logf.NewContext(ctx.RootContext, nil, ControllerName)
	ctrl.metrics = metrics.Default

	return ctrl
}

// TODO: replace with generic handleObjet function (like Navigator)
func (c *Controller) secretDeleted(obj interface{}) {
	log := logf.FromContext(c.ctx)

	var secret *corev1.Secret
	var ok bool
	secret, ok = obj.(*corev1.Secret)
	if !ok {
		log.Error(nil, "object was not a secret object")
		return
	}
	log = logf.WithResource(log, secret)
	issuers, err := c.issuersForSecret(secret)
	if err != nil {
		log.Error(err, "error looking up issuers observing secret")
		return
	}
	for _, iss := range issuers {
		key, err := keyFunc(iss)
		if err != nil {
			log.Error(err, "error computing key for resource")
			continue
		}
		c.queue.AddRateLimited(key)
	}
}

func (c *Controller) Run(workers int, stopCh <-chan struct{}) error {
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	log := logf.FromContext(ctx)

	log.Info("starting control loop")
	// wait for all the informer caches we depend on are synced
	if !cache.WaitForCacheSync(stopCh, c.watchedInformers...) {
		// TODO: replace with Errorf call to glog
		return fmt.Errorf("error waiting for informer caches to sync")
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		// TODO (@munnerz): make time.Second duration configurable
		go wait.Until(func() {
			defer wg.Done()
			c.worker(ctx)
		}, time.Second, stopCh)
	}
	<-stopCh
	log.Info("shutting down queue as workqueue signaled shutdown")
	c.queue.ShutDown()
	log.V(logf.DebugLevel).Info("waiting for workers to exit...")
	wg.Wait()
	log.V(logf.DebugLevel).Info("workers exited")
	return nil
}

func (c *Controller) worker(ctx context.Context) {
	log := logf.FromContext(c.ctx)

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
			log.Info("syncing item")
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

	issuer, err := c.issuerLister.Issuers(namespace).Get(name)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			log.Error(err, "issuer in work queue no longer exists")
			return nil
		}

		return err
	}

	ctx = logf.NewContext(ctx, logf.WithResource(log, issuer))
	return c.Sync(ctx, issuer)
}

var keyFunc = controllerpkg.KeyFunc

const (
	ControllerName = "issuers"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return New(ctx).Run, nil
	})
}
