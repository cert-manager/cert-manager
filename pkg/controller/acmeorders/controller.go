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

package acmeorders

import (
	"context"
	"fmt"
	"sync"
	"time"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	"github.com/jetstack/cert-manager/pkg/acme"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

type Controller struct {
	// the controllers root context, containing a controller scoped logger
	ctx context.Context
	controllerpkg.Context

	helper     issuer.Helper
	acmeHelper acme.Helper

	// To allow injection for testing.
	syncHandler func(ctx context.Context, key string) error

	orderLister         cmlisters.OrderLister
	challengeLister     cmlisters.ChallengeLister
	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
	secretLister        corelisters.SecretLister

	watchedInformers []cache.InformerSynced
	queue            workqueue.RateLimitingInterface

	// used for testing
	clock clock.Clock
}

func New(ctx *controllerpkg.Context) *Controller {
	ctrl := &Controller{Context: *ctx}
	ctrl.syncHandler = ctrl.processNextWorkItem

	ctrl.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*5, time.Minute*30), "orders")

	orderInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().Orders()
	orderInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
	ctrl.watchedInformers = append(ctrl.watchedInformers, orderInformer.Informer().HasSynced)
	ctrl.orderLister = orderInformer.Lister()

	issuerInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().Issuers()
	issuerInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: ctrl.handleGenericIssuer})
	ctrl.watchedInformers = append(ctrl.watchedInformers, issuerInformer.Informer().HasSynced)
	ctrl.issuerLister = issuerInformer.Lister()

	if ctx.Namespace == "" {
		clusterIssuerInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers()
		clusterIssuerInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: ctrl.handleGenericIssuer})
		ctrl.watchedInformers = append(ctrl.watchedInformers, clusterIssuerInformer.Informer().HasSynced)
		ctrl.clusterIssuerLister = clusterIssuerInformer.Lister()
	}

	challengeInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().Challenges()
	challengeInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: ctrl.handleOwnedResource})
	ctrl.watchedInformers = append(ctrl.watchedInformers, challengeInformer.Informer().HasSynced)
	ctrl.challengeLister = challengeInformer.Lister()

	// TODO: detect changes to secrets referenced by order's issuers.
	secretInformer := ctrl.KubeSharedInformerFactory.Core().V1().Secrets()
	ctrl.watchedInformers = append(ctrl.watchedInformers, secretInformer.Informer().HasSynced)
	ctrl.secretLister = secretInformer.Lister()

	ctrl.helper = issuer.NewHelper(ctrl.issuerLister, ctrl.clusterIssuerLister)
	ctrl.acmeHelper = acme.NewHelper(ctrl.secretLister, ctrl.Context.ClusterResourceNamespace)
	ctrl.clock = clock.RealClock{}
	ctrl.ctx = logf.NewContext(ctx.RootContext, nil, ControllerName)

	return ctrl
}

func (c *Controller) handleOwnedResource(obj interface{}) {
	log := logf.FromContext(c.ctx, "handleOwnedResource")

	metaobj, ok := obj.(metav1.Object)
	if !ok {
		log.Error(nil, "item passed to handleOwnedResource does not implement metav1.Object")
		return
	}
	log = logf.WithResource(log, metaobj)

	ownerRefs := metaobj.GetOwnerReferences()
	for _, ref := range ownerRefs {
		log := log.WithValues(
			logf.RelatedResourceNamespaceKey, metaobj.GetNamespace(),
			logf.RelatedResourceNameKey, ref.Name,
			logf.RelatedResourceKindKey, ref.Kind,
		)

		// Parse the Group out of the OwnerReference to compare it to what was parsed out of the requested OwnerType
		refGV, err := schema.ParseGroupVersion(ref.APIVersion)
		if err != nil {
			log.Error(err, "could not parse OwnerReference GroupVersion")
			continue
		}

		if refGV.Group == orderGvk.Group && ref.Kind == orderGvk.Kind {
			// TODO: how to handle namespace of owner references?
			order, err := c.orderLister.Orders(metaobj.GetNamespace()).Get(ref.Name)
			if err != nil {
				log.Error(err, "error getting order referenced by resource")
				continue
			}
			objKey, err := keyFunc(order)
			if err != nil {
				log.Error(err, "error computing key for resource")
				continue
			}
			c.queue.Add(objKey)
		}
	}
}

func (c *Controller) Run(workers int, stopCh <-chan struct{}) error {
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	log := logf.FromContext(ctx)

	log.V(logf.DebugLevel).Info("starting %s control loop")
	// wait for all the informer caches we depend on are synced
	if !cache.WaitForCacheSync(stopCh, c.watchedInformers...) {
		// c.challengeInformerSynced) {
		return fmt.Errorf("error waiting for informer caches to sync")
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		// TODO (@munnerz): make time.Second duration configurable
		go wait.Until(func() {
			defer wg.Done()
			c.worker(ctx)
		},
			time.Second, stopCh)
	}
	<-stopCh
	log.V(logf.DebugLevel).Info("shutting down queue as workqueue signaled shutdown")
	c.queue.ShutDown()
	log.V(logf.DebugLevel).Info("waiting for workers to exit...")
	wg.Wait()
	log.V(logf.DebugLevel).Info("workers exited")
	return nil
}

func (c *Controller) worker(ctx context.Context) {
	log := logf.FromContext(ctx)

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

	order, err := c.orderLister.Orders(namespace).Get(name)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			log.Error(err, "order in work queue no longer exists")
			return nil
		}

		return err
	}

	ctx = logf.NewContext(ctx, logf.WithResource(log, order))
	return c.Sync(ctx, order)
}

var keyFunc = controllerpkg.KeyFunc

const (
	ControllerName = "orders"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return New(ctx).Run, nil
	})
}
