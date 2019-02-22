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

package clusterissuers

import (
	"context"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util"
)

type Controller struct {
	controllerpkg.Context
	issuerFactory issuer.IssuerFactory

	// To allow injection for testing.
	syncHandler func(ctx context.Context, key string) error

	clusterIssuerLister cmlisters.ClusterIssuerLister
	secretLister        corelisters.SecretLister

	watchedInformers []cache.InformerSynced
	queue            workqueue.RateLimitingInterface
}

func New(ctx *controllerpkg.Context) *Controller {
	ctrl := &Controller{Context: *ctx}
	ctrl.syncHandler = ctrl.processNextWorkItem
	ctrl.queue = workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), "clusterissuers")

	clusterIssuerInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers()
	clusterIssuerInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
	ctrl.watchedInformers = append(ctrl.watchedInformers, clusterIssuerInformer.Informer().HasSynced)
	ctrl.clusterIssuerLister = clusterIssuerInformer.Lister()

	secretsInformer := ctrl.KubeSharedInformerFactory.Core().V1().Secrets()
	secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: ctrl.secretDeleted})
	ctrl.watchedInformers = append(ctrl.watchedInformers, secretsInformer.Informer().HasSynced)
	ctrl.secretLister = secretsInformer.Lister()
	ctrl.issuerFactory = issuer.NewIssuerFactory(ctx)

	return ctrl
}

// TODO: replace with generic handleObjet function (like Navigator)
func (c *Controller) secretDeleted(obj interface{}) {
	var secret *corev1.Secret
	var ok bool
	secret, ok = obj.(*corev1.Secret)
	if !ok {
		runtime.HandleError(fmt.Errorf("Object was not a Secret object %#v", obj))
		return
	}
	issuers, err := c.issuersForSecret(secret)
	if err != nil {
		runtime.HandleError(fmt.Errorf("Error looking up issuers observing Secret: %s/%s", secret.Namespace, secret.Name))
		return
	}
	for _, iss := range issuers {
		key, err := keyFunc(iss)
		if err != nil {
			runtime.HandleError(err)
			continue
		}
		c.queue.AddRateLimited(key)
	}
}

func (c *Controller) Run(workers int, stopCh <-chan struct{}) error {
	klog.V(4).Infof("Starting %s control loop", ControllerName)
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
			c.worker(stopCh)
		}, time.Second, stopCh)
	}
	<-stopCh
	klog.V(4).Infof("Shutting down queue as workqueue signaled shutdown")
	c.queue.ShutDown()
	klog.V(4).Infof("Waiting for workers to exit...")
	wg.Wait()
	klog.V(4).Infof("Workers exited.")
	return nil
}

func (c *Controller) worker(stopCh <-chan struct{}) {
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
	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	issuer, err := c.clusterIssuerLister.Get(name)

	if err != nil {
		if k8sErrors.IsNotFound(err) {
			runtime.HandleError(fmt.Errorf("issuer %q in work queue no longer exists", key))
			return nil
		}

		return err
	}

	return c.Sync(ctx, issuer)
}

var keyFunc = controllerpkg.KeyFunc

const (
	ControllerName = "clusterissuers"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) controllerpkg.Interface {
		return New(ctx).Run
	})
}
