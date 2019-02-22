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

package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	extlisters "k8s.io/client-go/listers/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	cmv1alpha1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cminformers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions/certmanager/v1alpha1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util"
	extinformers "k8s.io/client-go/informers/extensions/v1beta1"
)

const (
	ControllerName = "ingress-shim"
)

type defaults struct {
	autoCertificateAnnotations  []string
	issuerName, issuerKind      string
	acmeIssuerChallengeType     string
	acmeIssuerDNS01ProviderName string
}

type Controller struct {
	Client   kubernetes.Interface
	CMClient clientset.Interface
	Recorder record.EventRecorder

	helper issuer.Helper

	// To allow injection for testing.
	syncHandler func(ctx context.Context, key string) error

	ingressLister       extlisters.IngressLister
	certificateLister   cmlisters.CertificateLister
	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister

	queue       workqueue.RateLimitingInterface
	workerWg    sync.WaitGroup
	syncedFuncs []cache.InformerSynced
	defaults    defaults
}

// New returns a new Certificates controller. It sets up the informer handler
// functions for all the types it watches.
func New(
	certificatesInformer cminformers.CertificateInformer,
	ingressInformer extinformers.IngressInformer,
	issuerInformer cminformers.IssuerInformer,
	clusterIssuerInformer cminformers.ClusterIssuerInformer,
	client kubernetes.Interface,
	cmClient clientset.Interface,
	recorder record.EventRecorder,
	defaults defaults,
) *Controller {
	ctrl := &Controller{Client: client, CMClient: cmClient, Recorder: recorder, defaults: defaults}
	ctrl.syncHandler = ctrl.processNextWorkItem
	ctrl.queue = workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), "ingresses")

	ingressInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
	ctrl.ingressLister = ingressInformer.Lister()
	ctrl.syncedFuncs = append(ctrl.syncedFuncs, ingressInformer.Informer().HasSynced)

	certificatesInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: ctrl.certificateDeleted})
	ctrl.certificateLister = certificatesInformer.Lister()
	ctrl.syncedFuncs = append(ctrl.syncedFuncs, certificatesInformer.Informer().HasSynced)

	ctrl.issuerLister = issuerInformer.Lister()
	ctrl.syncedFuncs = append(ctrl.syncedFuncs, issuerInformer.Informer().HasSynced)

	if clusterIssuerInformer != nil {
		ctrl.clusterIssuerLister = clusterIssuerInformer.Lister()
		ctrl.syncedFuncs = append(ctrl.syncedFuncs, clusterIssuerInformer.Informer().HasSynced)
	}

	ctrl.helper = issuer.NewHelper(ctrl.issuerLister, ctrl.clusterIssuerLister)

	return ctrl
}

func (c *Controller) certificateDeleted(obj interface{}) {
	crt, ok := obj.(*cmv1alpha1.Certificate)
	if !ok {
		runtime.HandleError(fmt.Errorf("Object is not a certificate object %#v", obj))
		return
	}
	ings, err := c.ingressesForCertificate(crt)
	if err != nil {
		runtime.HandleError(fmt.Errorf("Error looking up ingress observing certificate: %s/%s", crt.Namespace, crt.Name))
		return
	}
	for _, crt := range ings {
		key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(crt)
		if err != nil {
			runtime.HandleError(err)
			continue
		}
		c.queue.Add(key)
	}
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

	crt, err := c.ingressLister.Ingresses(namespace).Get(name)

	if err != nil {
		if k8sErrors.IsNotFound(err) {
			runtime.HandleError(fmt.Errorf("ingress '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	return c.Sync(ctx, crt)
}

var keyFunc = controllerpkg.KeyFunc

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) controllerpkg.Interface {
		var clusterIssuerInformer cminformers.ClusterIssuerInformer
		if ctx.Namespace == "" {
			clusterIssuerInformer = ctx.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers()
		}
		return New(
			ctx.SharedInformerFactory.Certmanager().V1alpha1().Certificates(),
			ctx.KubeSharedInformerFactory.Extensions().V1beta1().Ingresses(),
			ctx.SharedInformerFactory.Certmanager().V1alpha1().Issuers(),
			clusterIssuerInformer,
			ctx.Client,
			ctx.CMClient,
			ctx.Recorder,
			defaults{ctx.DefaultAutoCertificateAnnotations, ctx.DefaultIssuerName, ctx.DefaultIssuerKind, ctx.DefaultACMEIssuerChallengeType, ctx.DefaultACMEIssuerDNS01ProviderName},
		).Run
	})
}
