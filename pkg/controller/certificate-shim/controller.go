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

// Package controller implements the certificate-shim controllers -
// ingress-shim and gateway-shim.
//
// A common use-case for cert-manager is to easily create publicly
// trusted ACME certificates for services hosted inside a Kubernetes
// cluster. The ingress-shim and gateway-shim controllers allow you
// to annotate your Ingress or Gateway with a reference to a
// cert-manager (Cluster)Issuer, which will automatically create a
// corresponding cert-manager Certificate.
//
// This controller package contains a generic runtime.Object
// certificate-shim controller, which should be embedded for each
// Kubernetes API type that can be shimmed.
package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	gatewayapi "sigs.k8s.io/gateway-api/apis/v1alpha1"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

const (
	// IngressShimControllerName is the name of the ingress-shim controller.
	IngressShimControllerName = "ingress-shim"

	// GatewayShimControllerName is the name of the gateway-shim controller.
	GatewayShimControllerName = "gateway-shim"

	// resyncPeriod is set to 10 hours following the controller-runtime defaults
	// and following discussion: https://github.com/kubernetes-sigs/controller-runtime/pull/88#issuecomment-408500629
	// which boils down to: never change this without an explicit reason
	resyncPeriod = 10 * time.Hour
)

// defaults can be reconfigure from command line flags. They exist to
// maintain compatibility with the kube-lego `kubernetes.io/tls-acme`
// annotation by providing a reference to a default issuer.
type defaults struct {
	autoCertificateAnnotations          []string
	issuerName, issuerKind, issuerGroup string
}

// controller is a generic certificate-shim controller.
//
// By setting controller.objectLister and controller.objectInformer
// to watch / list any Kubernetes API type, the controller will
// react to any changes to those types, check for supported
// annotations and create matching certificates.
type controller struct {
	// queue is a reference to the workqueue for this controller
	// so the handleOwnedResource method can enqueue resources.
	queue workqueue.RateLimitingInterface

	// logger to be used by this controller
	log logr.Logger

	kClient  kubernetes.Interface
	cmClient clientset.Interface
	recorder record.EventRecorder

	objectLister        objectLister
	objectInformer      cache.SharedIndexInformer
	certificateLister   cmlisters.CertificateLister
	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister

	helper   issuer.Helper
	defaults defaults
}

// ingressShim is the ingress-shim variant of certificate-shim
type ingressShim struct {
	controller
}

// Register sets up a certificate-shim for *networkingv1beta1.Ingresses
func (i *ingressShim) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	i.log = logf.FromContext(ctx.RootContext, IngressShimControllerName)
	i.queue = workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), IngressShimControllerName)

	ingressInformer := ctx.KubeSharedInformerFactory.Networking().V1beta1().Ingresses()
	i.objectInformer = ingressInformer.Informer()
	i.objectLister = &internalIngressLister{ingressInformer.Lister()}

	return i.sharedRegister(ctx)
}

// gatewayShim is the gateway-shim variant of certificate-shim
type gatewayShim struct {
	controller
}

// Register sets up a certificate-shim for *gatewayapi.Gateways
func (g *gatewayShim) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	g.log = logf.FromContext(ctx.RootContext, GatewayShimControllerName)
	g.queue = workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), GatewayShimControllerName)

	// If the gateway-shim controller is enabled, but the CRDs have not been installed, return an error
	// prompting the user to install the CRDs. This will cause cert-manager to go in to CrashLoopBackoff
	// which is nice and obvious.

	// Use the discovery client to find out if the Gateway API types are known to the API server
	d, err := discovery.NewDiscoveryClientForConfig(ctx.RESTConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: couldn't construct discovery client: %w", GatewayShimControllerName, err)
	}
	resources, err := d.ServerResourcesForGroupVersion(gatewayapi.GroupVersion.String())
	if err != nil {
		return nil, nil, fmt.Errorf("%s: couldn't discover gateway API resources (are the Gateway API CRDS installed?): %w", GatewayShimControllerName, err)
	}
	if len(resources.APIResources) == 0 {
		return nil, nil, fmt.Errorf("%s: no gateway API resources were discovered (are the Gateway API CRDS installed?)", GatewayShimControllerName)
	}

	// As gateways are a CRD their informers are not available in controllerpkg.Context,
	// create a new InformerFactory for gatewayapi.Gateways and set the certificate-shim
	// objectInformer / objectLister to use them.
	gatewayInformerFactory := gatewayinformers.NewSharedInformerFactory(gatewayclient.NewForConfigOrDie(ctx.RESTConfig), resyncPeriod)
	gatewayInformerLister := gatewayInformerFactory.Networking().V1alpha1().Gateways()
	g.objectInformer = gatewayInformerLister.Informer()
	g.objectLister = &internalGatewayLister{gatewayInformerLister.Lister()}

	gatewayInformerFactory.Start(ctx.StopCh)
	return g.sharedRegister(ctx)
}

// sharedRegister registers and constructs the certificate-shim controller using the provided context.
// It should be called from the Register() function of a controller implementing a certificate-shim.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
func (c *controller) sharedRegister(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	certificatesInformer := ctx.SharedInformerFactory.Certmanager().V1().Certificates()
	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1().Issuers()
	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		c.objectInformer.HasSynced,
		certificatesInformer.Informer().HasSynced,
		issuerInformer.Informer().HasSynced,
	}

	// set all the references to the listers for used by the Sync function
	c.certificateLister = certificatesInformer.Lister()
	c.issuerLister = issuerInformer.Lister()

	// if we are running in non-namespaced mode (i.e. --namespace=""), we also
	// register event handlers and obtain a lister for clusterissuers.
	if ctx.Namespace == "" {
		clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1().ClusterIssuers()
		mustSync = append(mustSync, clusterIssuerInformer.Informer().HasSynced)
		c.clusterIssuerLister = clusterIssuerInformer.Lister()
	}

	// register handler functions
	c.objectInformer.AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue})
	certificatesInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.certificateDeleted})

	c.helper = issuer.NewHelper(c.issuerLister, c.clusterIssuerLister)
	c.kClient = ctx.Client
	c.cmClient = ctx.CMClient
	c.recorder = ctx.Recorder
	c.defaults = defaults{
		ctx.DefaultAutoCertificateAnnotations,
		ctx.DefaultIssuerName,
		ctx.DefaultIssuerKind,
		ctx.DefaultIssuerGroup,
	}

	return c.queue, mustSync, nil
}

func (c *controller) certificateDeleted(obj interface{}) {
	crt, ok := obj.(*cmapi.Certificate)
	if !ok {
		runtime.HandleError(fmt.Errorf("Object is not a certificate object %#v", obj))
		return
	}
	objs, err := c.ownersOfCertificate(crt)
	if err != nil {
		runtime.HandleError(fmt.Errorf("Error looking up ingress observing certificate: %s/%s", crt.Namespace, crt.Name))
		return
	}
	for _, o := range objs {
		key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(o)
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

	obj, err := c.objectLister.Objects(namespace).Get(name)

	if err != nil {
		if k8sErrors.IsNotFound(err) {
			runtime.HandleError(fmt.Errorf("object '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	return c.Sync(ctx, obj)
}

func init() {
	controllerpkg.Register(IngressShimControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, IngressShimControllerName).
			For(&ingressShim{}).
			Complete()
	})
	controllerpkg.Register(GatewayShimControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, GatewayShimControllerName).
			For(&gatewayShim{}).
			Complete()
	})
}
