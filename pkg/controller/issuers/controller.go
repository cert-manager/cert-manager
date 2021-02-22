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

package issuers

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	internalissuers "github.com/jetstack/cert-manager/pkg/controller/internal/issuers"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

// Issuer implements the actual issuer that backs a [Cluster]Issuer resource.
type Issuer interface {
	// Setup initialises the issuer. This may include registering accounts with
	// a service, creating a CA and storing it somewhere, or verifying
	// credentials and authorization with a remote server.
	Setup(context.Context, cmapi.GenericIssuer) error

	// Implements is a func called to determine whether the given generic issuer
	// implements the type that the Issuer controls. If returns true, this Issuer
	// implements this generic issuer spec type.
	Implements(cmapi.GenericIssuer) bool

	// ReferencesSecret is a func called to determine whether the given secret is
	// affected by the given issuer for this Issuer.
	ReferencesSecret(cmapi.GenericIssuer, *corev1.Secret) bool
}

// Controller is the generic issuer controller that handles generic Issuer
// resouces.
type Controller struct {
	name string
	// Either Issuer or ClusterIssuer
	issuerKind string

	// logger to be used by this controller
	log logr.Logger

	// issuerBackend holds the actual backend implementation of the issuer
	issuerBackend Issuer

	// lister is a generic interface issuer lister for getting Issuer or Cluster
	// Issuers
	issuerLister internalissuers.Lister
	secretLister corelisters.SecretLister

	// clientset used to update cert-manager API resources
	cmClient cmclient.Interface

	issuerInformer internalissuers.Informer

	// maintain a reference to the workqueue for this controller so we can
	// enqueue [Cluster]Issuers affected by other resources.
	queue workqueue.RateLimitingInterface

	issuerOptions controllerpkg.IssuerOptions

	// Extra informers that should be watched by this issuer controller instance.
	// These resources can be owned by [Cluster]Issuers that we resolve.
	// TODO: introduce extra informers if issuers require more informers than
	// just [Cluster]Issuers and secrets. For example, Vault Issuers using
	// ServiceAccount authentication.
	//extraInformers []cache.SharedIndexInformer
}

func New(name, issuerKind string, issuerBackend Issuer) *Controller {
	return &Controller{
		name:          name,
		issuerKind:    issuerKind,
		issuerBackend: issuerBackend,
	}
}

// Register will construct and register the Issuer and Cluster issuer
// controller for the issuer backend defined.
func (c *Controller) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	c.log = logf.FromContext(ctx.RootContext)

	secretInformer := ctx.KubeSharedInformerFactory.Core().V1().Secrets()

	// Add event handler for checking secrets that may effect [Cluster]issuers
	c.secretLister = secretInformer.Lister()
	secretInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.secretChecker})

	switch c.issuerKind {
	case cmapi.IssuerKind:
		c.issuerInformer = internalissuers.NewIssuerInformer(
			ctx.SharedInformerFactory.Certmanager().V1().Issuers())
	case cmapi.ClusterIssuerKind:
		c.issuerInformer = internalissuers.NewClusterIssuerInformer(
			ctx.SharedInformerFactory.Certmanager().V1().ClusterIssuers())
	default:
		return nil, nil, fmt.Errorf("unrecognised issuer kind: %s", c.issuerKind)
	}

	c.issuerLister = c.issuerInformer.Lister()

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := append([]cache.InformerSynced{
		c.issuerInformer.Informer().HasSynced,
		secretInformer.Informer().HasSynced,
	})

	c.issuerOptions = ctx.IssuerOptions

	c.queue = workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), c.name)
	c.cmClient = ctx.CMClient
	c.issuerInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue})

	return c.queue, mustSync, nil
}

func (c *Controller) ProcessItem(ctx context.Context, key string) error {
	log := logf.FromContext(ctx)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "invalid resource key")
		return nil
	}

	issuer, err := c.issuerLister.Get(namespace, name)
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
// secret are enqueued
func (c *Controller) secretChecker(obj interface{}) {
	for _, key := range c.AffectedSecret(obj) {
		c.queue.AddRateLimited(key)
	}
}

// AffectedSecret returns a list of keys which are affected by the given
// secret
func (c *Controller) AffectedSecret(obj interface{}) []string {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		c.log.Error(nil, "secretChecker called with non Secret resource")
		return nil
	}

	log := logf.WithResource(c.log, secret)

	issuersToCheck, err := c.issuerLister.List(labels.NewSelector())
	if err != nil {
		log.Error(err, "error looking up Issuers observing secret")
		return nil
	}

	var keys []string
	for _, issuer := range issuersToCheck {
		log := logf.WithResource(log, issuer)

		// If the secret Namespace does not match the Issuer resource namespace then
		// continue early.
		if secret.Namespace != c.issuerOptions.ResourceNamespace(issuer) {
			continue
		}

		// If the issuer backend is affected by this secret resource given the
		// issuer, enqueue.
		if c.issuerBackend.ReferencesSecret(issuer, secret) {
			key, err := controllerpkg.KeyFunc(issuer)
			if err != nil {
				log.Error(err, "error computing key for resource")
				continue
			}

			keys = append(keys, key)
		}
	}

	return keys
}
