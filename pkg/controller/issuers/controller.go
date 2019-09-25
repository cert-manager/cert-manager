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

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha2"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

type controller struct {
	issuerLister cmlisters.IssuerLister
	secretLister corelisters.SecretLister

	// maintain a reference to the workqueue for this controller
	// so the handleOwnedResource method can enqueue resources
	queue workqueue.RateLimitingInterface

	// logger to be used by this controller
	log logr.Logger

	// clientset used to update cert-manager API resources
	cmClient cmclient.Interface

	// used to record Events about resources to the API
	recorder record.EventRecorder

	// issuerFactory is used to obtain a reference to the Issuer implementation
	// for each ClusterIssuer resource
	issuerFactory issuer.Factory
}

// Register registers and constructs the controller using the provided context.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
func (c *controller) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, []controllerpkg.RunFunc, error) {
	// construct a new named logger to be reused throughout the controller
	c.log = logf.FromContext(ctx.RootContext, ControllerName)

	// create a queue used to queue up items to be processed
	c.queue = workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), ControllerName)

	// obtain references to all the informers used by this controller
	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha2().Issuers()
	secretInformer := ctx.KubeSharedInformerFactory.Core().V1().Secrets()
	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		issuerInformer.Informer().HasSynced,
		secretInformer.Informer().HasSynced,
	}

	// set all the references to the listers for used by the Sync function
	c.issuerLister = issuerInformer.Lister()
	c.secretLister = secretInformer.Lister()

	// register handler functions
	issuerInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue})
	secretInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.secretDeleted})

	// instantiate additional helpers used by this controller
	c.issuerFactory = issuer.NewFactory(ctx)
	c.cmClient = ctx.CMClient
	c.recorder = ctx.Recorder

	return c.queue, mustSync, nil, nil
}

// TODO: replace with generic handleObjet function (like Navigator)
func (c *controller) secretDeleted(obj interface{}) {
	log := c.log.WithName("secretDeleted")

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

func (c *controller) ProcessItem(ctx context.Context, key string) error {
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
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&controller{}).
			Complete()
	})
}
