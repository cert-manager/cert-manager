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

	"github.com/go-logr/logr"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	extlisters "k8s.io/client-go/listers/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	cmv1alpha1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
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

type controller struct {
	// maintain a reference to the workqueue for this controller
	// so the handleOwnedResource method can enqueue resources
	queue workqueue.RateLimitingInterface

	// logger to be used by this controller
	log logr.Logger

	kClient  kubernetes.Interface
	cmClient clientset.Interface
	recorder record.EventRecorder

	ingressLister       extlisters.IngressLister
	certificateLister   cmlisters.CertificateLister
	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister

	helper   issuer.Helper
	defaults defaults
}

// Register registers and constructs the controller using the provided context.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
func (c *controller) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	c.log = logf.FromContext(ctx.RootContext, ControllerName)

	// create a queue used to queue up items to be processed
	c.queue = workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), ControllerName)

	// obtain references to all the informers used by this controller
	ingressInformer := ctx.KubeSharedInformerFactory.Extensions().V1beta1().Ingresses()
	certificatesInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Certificates()
	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Issuers()
	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		ingressInformer.Informer().HasSynced,
		certificatesInformer.Informer().HasSynced,
		issuerInformer.Informer().HasSynced,
	}

	// set all the references to the listers for used by the Sync function
	c.ingressLister = ingressInformer.Lister()
	c.certificateLister = certificatesInformer.Lister()
	c.issuerLister = issuerInformer.Lister()

	// if scoped to a single namespace
	// if we are running in non-namespaced mode (i.e. --namespace=""), we also
	// register event handlers and obtain a lister for clusterissuers.
	if ctx.Namespace == "" {
		clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers()
		mustSync = append(mustSync, clusterIssuerInformer.Informer().HasSynced)
		c.clusterIssuerLister = clusterIssuerInformer.Lister()
	}

	// register handler functions
	ingressInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue})
	certificatesInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.certificateDeleted})

	c.helper = issuer.NewHelper(c.issuerLister, c.clusterIssuerLister)
	c.kClient = ctx.Client
	c.cmClient = ctx.CMClient
	c.recorder = ctx.Recorder
	c.defaults = defaults{
		ctx.DefaultAutoCertificateAnnotations,
		ctx.DefaultIssuerName,
		ctx.DefaultIssuerKind,
		ctx.DefaultACMEIssuerChallengeType,
		ctx.DefaultACMEIssuerDNS01ProviderName,
	}

	return c.queue, mustSync, nil
}

func (c *controller) certificateDeleted(obj interface{}) {
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
	for _, ing := range ings {
		key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(ing)
		if err != nil {
			runtime.HandleError(err)
			continue
		}
		c.queue.Add(key)
	}
}

func (c *controller) ProcessItem(ctx context.Context, key string) error {
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
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		c, err := controllerpkg.New(ctx, ControllerName, &controller{})
		if err != nil {
			return nil, err
		}
		return c.Run, nil
	})
}
