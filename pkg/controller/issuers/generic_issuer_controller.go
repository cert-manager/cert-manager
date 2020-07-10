/*
Copyright 2020 The Jetstack cert-manager contributors.

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

	"github.com/go-logr/logr"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"

	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/issuers/internal/generic"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

// IssuerBackend implements the actual Isser that backs give [Cluster]Issuer
// resources.
type IssuerBackend interface {
	// Setup initialises the issuer. This may include registering accounts with
	// a service, creating a CA and storing it somewhere, or verifying
	// credentials and authorization with a remote server.
	Setup(context.Context, cmapi.GenericIssuer) error

	// TypeChecker is a func called to determine whether the given generic issuer
	// is of the type that the IssuerBackend controls. If returns true, this
	// IssuerBackend implements this generic issuer spec type.
	TypeChecker(issuer cmapi.GenericIssuer) bool

	// SecretChecker is a func called to determine whether the given secret is
	// affected by the given issuer for this IssuerBackend. If returns true, a
	// the issuer is enqueued for its controller.
	SecretChecker(issuer cmapi.GenericIssuer, secret *corev1.Secret) bool
}

// IssuerBackendContructor is a func used to construct an issuer backend
// implementation using the controller context during registration.
type IssuerBackendContructor func(*controllerpkg.Context) IssuerBackend

// GenericController is the generic issuer controller than handles both Issuer
// and ClusterIssuer resources.
type GenericController struct {
	// logger to be used by this controller
	log logr.Logger

	issuerOptions controllerpkg.IssuerOptions

	// issuerContructor is a constructor for creating a shared issuer backend for
	// both issuer controllers
	issuerContructor IssuerBackendContructor

	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
	secretLister        corelisters.SecretLister

	issuerController, clusterIssuerController *controller

	// issuerBackend holds the actual backend implementation of the issuer
	issuerBackend IssuerBackend

	// Extra informers that should be watched by this issuer controller instance.
	// These resources can be owned by [Cluster]Issuers that we resolve.
	// TODO: introduce extra informers if issuers require more informers than
	// just [Cluster]Issuers and secrets. For example, Vault Issuers using
	// ServiceAccount authentication.
	//extraInformers []cache.SharedIndexInformer

	// registered denoted whether the generic controller has already been registered
	registered bool
}

// controller implements the underlying issuer controller for either Issuer or
// ClusterIssuer resources.
type controller struct {
	// name of this controller
	name string

	// issuerBackend holds the actual backend implementation of the issuer
	issuerBackend IssuerBackend

	// mustSync is a list of informers to be used for this controller queue
	mustSync []cache.InformerSynced

	// lister is a generic interface issuer lister for getting Issuer or Cluster
	// Issuers
	lister generic.IssuerLister

	// clientset used to update cert-manager API resources
	cmClient cmclient.Interface

	// infomer used to use queue
	informer cache.SharedIndexInformer

	// maintain a reference to the workqueue for this controller so we can
	// enqueue [Cluster]Issuers affected by other resources.
	queue workqueue.RateLimitingInterface
}

// RegisterIssuerBackend will create a new generic issuer controller for both
// Issuer and ClusterIssuer resources.
func RegisterIssuerBackend(issuerControllerName, clusterIssuerControllerName string, issuerContructor IssuerBackendContructor) {
	c := &GenericController{
		issuerContructor: issuerContructor,
	}

	// build Issuer and ClusterIssuer controllers for this issuer backend
	controllerpkg.Register(issuerControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		c.Register(ctx, issuerControllerName, clusterIssuerControllerName)
		return controllerpkg.NewBuilder(ctx, issuerControllerName).
			For(c.issuerController).Complete()
	})
	controllerpkg.Register(clusterIssuerControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		c.Register(ctx, issuerControllerName, clusterIssuerControllerName)
		return controllerpkg.NewBuilder(ctx, clusterIssuerControllerName).
			For(c.clusterIssuerController).Complete()
	})
}

// Register will construct and register the Issuer and Cluster issuer
// controller for the issuer backend defined.
func (c *GenericController) Register(ctx *controllerpkg.Context, issuerControllerName, clusterIssuerControllerName string) {
	// If generic controller has already been registered, exit early
	if c.registered {
		return
	}

	// construct a new named logger to be reused throughout the controller
	c.log = logf.FromContext(ctx.RootContext)

	// Build [Cluster]Issuer and secrets Informers + Listers
	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha2().Issuers()
	clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha2().ClusterIssuers()
	secretInformer := ctx.KubeSharedInformerFactory.Core().V1().Secrets()

	// Add event handler for checking secrets that may effect [Cluster]issuers
	c.secretLister = secretInformer.Lister()
	secretInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.secretChecker})

	c.issuerLister = issuerInformer.Lister()
	c.clusterIssuerLister = clusterIssuerInformer.Lister()

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := append([]cache.InformerSynced{
		issuerInformer.Informer().HasSynced,
		clusterIssuerInformer.Informer().HasSynced,
		secretInformer.Informer().HasSynced,
	})

	c.issuerBackend = c.issuerContructor(ctx)
	c.issuerOptions = ctx.IssuerOptions

	// construct the Issuer and ClusterIssuer controllers for the given issuer backend
	c.issuerController = &controller{
		name:          issuerControllerName,
		mustSync:      mustSync,
		lister:        generic.NewIssuerLister(c.issuerLister),
		informer:      issuerInformer.Informer(),
		cmClient:      ctx.CMClient,
		issuerBackend: c.issuerBackend,
	}
	c.clusterIssuerController = &controller{
		name:          clusterIssuerControllerName,
		mustSync:      mustSync,
		lister:        generic.NewClusterIssuerLister(c.clusterIssuerLister),
		informer:      clusterIssuerInformer.Informer(),
		cmClient:      ctx.CMClient,
		issuerBackend: c.issuerBackend,
	}

	c.registered = true

	c.log.Info("new issuer controllers registered",
		"issuer", issuerControllerName,
		"clusterissuer", clusterIssuerControllerName)

	return
}

// Register registers and constructs the controller using the provided context.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
// This controller will only implement a controller for either an Issuer and
// Controller Issuer.
func (c *controller) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	c.queue = workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), c.name)

	// register handler functions
	c.informer.AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue})

	return c.queue, c.mustSync, nil
}

func (c *controller) ProcessItem(ctx context.Context, key string) error {
	log := logf.FromContext(ctx)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "invalid resource key")
		return nil
	}

	issuer, err := c.lister.Get(namespace, name)
	if apierrors.IsNotFound(err) {
		// issuer has been deleted so ignore
		return nil
	}
	if err != nil {
		return err
	}

	ctx = logf.NewContext(ctx, logf.WithResource(log, issuer))
	return c.Sync(ctx, issuer)
}

// secretChecker will ensure that any issuer that has been effected by this
// secret is enqueued
func (c *GenericController) secretChecker(obj interface{}) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		c.log.Error(nil, "secretChecker called with non Secret resource")
		return
	}

	log := logf.WithResource(c.log, secret)

	issuersToCheck, err := c.issuerLister.List(labels.NewSelector())
	if err != nil {
		log.Error(err, "error looking up Issuers observing secret")
		return
	}
	for _, issuer := range issuersToCheck {
		if err := c.enqueueIfAffected(c.issuerController.queue, issuer, secret); err != nil {
			log.Error(err, "failed to enqueue from issuer affected by secret")
		}
	}

	clusterIssuersToCheck, err := c.clusterIssuerLister.List(labels.NewSelector())
	if err != nil {
		log.Error(err, "error looking up ClusterIssuers observing secret")
		return
	}
	for _, clusterIssuer := range clusterIssuersToCheck {
		if err := c.enqueueIfAffected(c.clusterIssuerController.queue, clusterIssuer, secret); err != nil {
			log.Error(err, "failed to enqueue from issuer affected by secret")
		}
	}
}

// enqueueIfAffected will enqueue the given issuer if it has been effected by
// this secret.
func (c *GenericController) enqueueIfAffected(queue workqueue.RateLimitingInterface, issuer cmapi.GenericIssuer, secret *corev1.Secret) error {
	// If the secret Namespace does not match the Issuer resource namespace then
	// exit early.
	if secret.Namespace != c.issuerOptions.ResourceNamespace(issuer) {
		return nil
	}

	// If the issuer backend is affected by this secret resource given the
	// issuer, enqueue.
	if c.issuerBackend.SecretChecker(issuer, secret) {
		key, err := controllerpkg.KeyFunc(issuer)
		if err != nil {
			return fmt.Errorf("error computing key for resource: %s", err)
		}

		queue.AddRateLimited(key)
	}

	return nil
}
