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

package certificaterequests

import (
	"context"

	"github.com/go-logr/logr"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
)

const (
	ControllerName = "certificaterequests"
)

var keyFunc = controllerpkg.KeyFunc

type Controller struct {
	helper issuer.Helper

	// clientset used to update cert-manager API resources
	cmClient cmclient.Interface

	certificateRequestLister cmlisters.CertificateRequestLister

	queue   workqueue.RateLimitingInterface
	metrics *metrics.Metrics

	// logger to be used by this controller
	log logr.Logger

	// used to record Events about resources to the API
	recorder record.EventRecorder

	// the issuer kind to react to when a certificate request is synced
	issuerType string

	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
	issuerFactory       issuer.IssuerFactory
}

func New(issuerType string) *Controller {
	return &Controller{
		issuerType: issuerType,
	}
}

// Register registers and constructs the controller using the provided context.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
func (c *Controller) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	c.log = logf.FromContext(ctx.RootContext, ControllerName)

	// create a queue used to queue up items to be processed
	c.queue = workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), ControllerName)

	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Issuers()
	c.issuerLister = issuerInformer.Lister()

	// obtain references to all the informers used by this controller
	certificateRequestInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().CertificateRequests()

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		certificateRequestInformer.Informer().HasSynced,
		issuerInformer.Informer().HasSynced,
	}

	// if scoped to a single namespace
	// if we are running in non-namespaced mode (i.e. --namespace=""), we also
	// register event handlers and obtain a lister for clusterissuers.
	if ctx.Namespace == "" {
		clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers()
		c.clusterIssuerLister = clusterIssuerInformer.Lister()
		// register handler function for clusterissuer resources
		clusterIssuerInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.handleGenericIssuer})
		mustSync = append(mustSync, clusterIssuerInformer.Informer().HasSynced)
	}

	// set all the references to the listers for used by the Sync function
	c.certificateRequestLister = certificateRequestInformer.Lister()

	// register handler functions
	certificateRequestInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue})

	// instantiate metrics interface with default metrics implementation
	c.metrics = metrics.Default

	// create an issuer helper for reading generic issuers
	c.helper = issuer.NewHelper(c.issuerLister, c.clusterIssuerLister)

	// issuerFactory provides an interface to obtain Issuer implementations from issuer resources
	c.issuerFactory = issuer.NewIssuerFactory(ctx)

	// recorder records events about resources to the Kubernetes api
	c.recorder = ctx.Recorder
	c.cmClient = ctx.CMClient

	c.log.Info("new certificate request controller registered",
		"type", c.issuerType)

	return c.queue, mustSync, nil
}

func (c *Controller) ProcessItem(ctx context.Context, key string) error {
	log := logf.FromContext(ctx)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "invalid resource key")
		return nil
	}

	cr, err := c.certificateRequestLister.CertificateRequests(namespace).Get(name)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			log.Error(err, "certificate request in work queue no longer exists")
			return nil
		}

		return err
	}

	ctx = logf.NewContext(ctx, logf.WithResource(log, cr))
	return c.Sync(ctx, cr)
}
