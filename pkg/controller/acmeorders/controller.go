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
	"time"

	"github.com/go-logr/logr"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	"github.com/jetstack/cert-manager/pkg/acme"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

type controller struct {
	// issuer helper is used to obtain references to issuers, used by Sync()
	helper issuer.Helper
	// acmehelper is used to obtain references to ACME clients
	acmeHelper acme.Helper

	// all the listers used by this controller
	orderLister         cmlisters.OrderLister
	challengeLister     cmlisters.ChallengeLister
	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
	secretLister        corelisters.SecretLister

	// used for testing
	clock clock.Clock
	// used to record Events about resources to the API
	recorder record.EventRecorder
	// clientset used to update cert-manager API resources
	cmClient cmclient.Interface

	// maintain a reference to the workqueue for this controller
	// so the handleOwnedResource method can enqueue resources
	queue workqueue.RateLimitingInterface

	// logger to be used by this controller
	log logr.Logger
}

// Register registers and constructs the controller using the provided context.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
func (c *controller) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	c.log = logf.FromContext(ctx.RootContext, ControllerName)

	// create a queue used to queue up items to be processed
	c.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*5, time.Minute*30), ControllerName)

	// obtain references to all the informers used by this controller
	orderInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Orders()
	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Issuers()
	challengeInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Challenges()
	secretInformer := ctx.KubeSharedInformerFactory.Core().V1().Secrets()
	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		orderInformer.Informer().HasSynced,
		issuerInformer.Informer().HasSynced,
		challengeInformer.Informer().HasSynced,
		secretInformer.Informer().HasSynced,
	}

	// set all the references to the listers for used by the Sync function
	c.orderLister = orderInformer.Lister()
	c.issuerLister = issuerInformer.Lister()
	c.challengeLister = challengeInformer.Lister()
	c.secretLister = secretInformer.Lister()

	// if we are running in non-namespaced mode (i.e. --namespace=""), we also
	// register event handlers and obtain a lister for clusterissuers.
	if ctx.Namespace == "" {
		clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers()
		mustSync = append(mustSync, clusterIssuerInformer.Informer().HasSynced)
		c.clusterIssuerLister = clusterIssuerInformer.Lister()
		// register handler function for clusterissuer resources
		clusterIssuerInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.handleGenericIssuer})
	}

	// register handler functions
	orderInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue})
	issuerInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.handleGenericIssuer})
	challengeInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		WorkFunc: controllerpkg.HandleOwnedResourceNamespacedFunc(c.log, c.queue, orderGvk, c.orderGetter),
	})

	// instantiate additional helpers used by this controller
	c.helper = issuer.NewHelper(c.issuerLister, c.clusterIssuerLister)
	c.acmeHelper = acme.NewHelper(c.secretLister, ctx.ClusterResourceNamespace)
	c.recorder = ctx.Recorder
	c.cmClient = ctx.CMClient
	c.clock = clock.RealClock{}

	return c.queue, mustSync, nil
}

func (c *controller) orderGetter(namespace, name string) (interface{}, error) {
	return c.orderLister.Orders(namespace).Get(name)
}

func (c *controller) ProcessItem(ctx context.Context, key string) error {
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
		c, err := controllerpkg.New(ctx, ControllerName, &controller{})
		if err != nil {
			return nil, err
		}
		return c.Run, nil
	})
}
