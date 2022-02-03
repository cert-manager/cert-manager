/*
Copyright 2020 The cert-manager Authors.

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
	"fmt"

	"github.com/go-logr/logr"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/util"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

var keyFunc = controllerpkg.KeyFunc

// Issuer implements the functionality to sign a certificate request for a
// particular issuer type.
type Issuer interface {
	Sign(context.Context, *v1.CertificateRequest, v1.GenericIssuer) (*issuer.IssueResponse, error)
}

// Issuer Contractor builds a Issuer instance using the given controller
// context.
type IssuerConstructor func(*controllerpkg.Context) Issuer

// Controller is an implementation of the queueingController for
// certificate requests.
type Controller struct {
	helper issuer.Helper

	// clientset used to update cert-manager API resources
	cmClient cmclient.Interface

	certificateRequestLister cmlisters.CertificateRequestLister

	queue workqueue.RateLimitingInterface

	// logger to be used by this controller
	log logr.Logger

	// used to record Events about resources to the API
	recorder record.EventRecorder

	// the issuer kind to react to when a certificate request is synced
	issuerType string

	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister

	// extraInformerResources are the set of resources which should cause
	// reconciles if owned by a CertifcateRequest.
	extraInformerResources []schema.GroupVersionResource

	// Issuer to call sign function
	issuerConstructor IssuerConstructor
	issuer            Issuer

	// used for testing
	clock clock.Clock

	reporter *util.Reporter
}

// New will construct a new certificaterequest controller using the given
// Issuer implementation.
// Note: the extraInformers passed here will be 'waited' for when starting to
// ensure their corresponding listers have synced.
// An event handler will then be set on these informers that automatically
// resyncs CertificateRequest resources that 'own' the objects in the informer.
// It's the callers responsibility to ensure the Run function on the informer
// is called in order to start the reflector. This is handled automatically
// when the informer factory's Start method is called, if the given informer
// was obtained using a SharedInformerFactory.
func New(issuerType string, issuerConstructor IssuerConstructor, extraInformerResources ...schema.GroupVersionResource) *Controller {
	return &Controller{
		issuerType:             issuerType,
		issuerConstructor:      issuerConstructor,
		extraInformerResources: extraInformerResources,
	}
}

// Register registers and constructs the controller using the provided context.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
func (c *Controller) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	componentName := "certificaterequests-issuer-" + c.issuerType

	// construct a new named logger to be reused throughout the controller
	c.log = logf.FromContext(ctx.RootContext, componentName)

	// create a queue used to queue up items to be processed
	c.queue = workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), componentName)

	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1().Issuers()
	c.issuerLister = issuerInformer.Lister()

	// obtain references to all the informers used by this controller
	certificateRequestInformer := ctx.SharedInformerFactory.Certmanager().V1().CertificateRequests()

	mustSync := []cache.InformerSynced{
		certificateRequestInformer.Informer().HasSynced,
		issuerInformer.Informer().HasSynced,
	}

	// build a list of InformerSynced functions that will be returned by the
	// Register method.  the controller will only begin processing items once all
	// of these informers have synced.

	// Ensure we also catch all extra informers for this CertificateRequest
	// controller instance.
	var extraInformers []cache.SharedIndexInformer
	for _, i := range c.extraInformerResources {
		// TODO (joshvanl): currently we only have an extra informer for
		// cert-manager Orders. If extended to other informer factory sets, add a
		// switch statement here for the group so that the correct shared informer
		// can be selected.
		extraInformer, err := ctx.SharedInformerFactory.ForResource(i)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get extra informer for %v: %w", i, err)
		}
		extraInformers = append(extraInformers, extraInformer.Informer())
		mustSync = append(mustSync, extraInformer.Informer().HasSynced)
	}

	// if scoped to a single namespace
	// if we are running in non-namespaced mode (i.e. --namespace=""), we also
	// register event handlers and obtain a lister for clusterissuers.
	if ctx.Namespace == "" {
		clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1().ClusterIssuers()
		c.clusterIssuerLister = clusterIssuerInformer.Lister()
		// register handler function for clusterissuer resources
		clusterIssuerInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.handleGenericIssuer})
		mustSync = append(mustSync, clusterIssuerInformer.Informer().HasSynced)
	}

	// set all the references to the listers for used by the Sync function
	c.certificateRequestLister = certificateRequestInformer.Lister()

	// register handler functions
	certificateRequestInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue})
	issuerInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.handleGenericIssuer})

	// Ensure we catch extra informers that are owned by certificate requests
	for _, i := range extraInformers {
		i.AddEventHandler(&controllerpkg.BlockingEventHandler{
			WorkFunc: controllerpkg.HandleOwnedResourceNamespacedFunc(c.log, c.queue, certificateRequestGvk, certificateRequestGetter(c.certificateRequestLister)),
		})
	}

	// create an issuer helper for reading generic issuers
	c.helper = issuer.NewHelper(c.issuerLister, c.clusterIssuerLister)

	// clock is used to set the FailureTime of failed CertificateRequests
	c.clock = ctx.Clock
	// recorder records events about resources to the Kubernetes api
	c.recorder = ctx.Recorder
	c.reporter = util.NewReporter(c.clock, c.recorder)
	c.cmClient = ctx.CMClient

	// Construct the issuer implementation with the built component context.
	c.issuer = c.issuerConstructor(ctx)

	c.log.V(logf.DebugLevel).Info("new certificate request controller registered",
		"type", c.issuerType)

	return c.queue, mustSync, nil
}

// ProcessItem is the worker function that will be called with a new key from
// the workqueue. A key corresponds to a certificate request object.
func (c *Controller) ProcessItem(ctx context.Context, key string) error {
	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "invalid resource key")
		return nil
	}

	cr, err := c.certificateRequestLister.CertificateRequests(namespace).Get(name)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			dbg.Info(fmt.Sprintf("certificate request in work queue no longer exists: %s", err))
			return nil
		}

		return err
	}

	ctx = logf.NewContext(ctx, logf.WithResource(log, cr))
	return c.Sync(ctx, cr)
}

func certificateRequestGetter(lister cmlisters.CertificateRequestLister) func(namespace, name string) (interface{}, error) {
	return func(namespace, name string) (interface{}, error) {
		return lister.CertificateRequests(namespace).Get(name)
	}
}
