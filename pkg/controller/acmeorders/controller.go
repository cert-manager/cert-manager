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

package acmeorders

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/informers"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	"github.com/cert-manager/cert-manager/pkg/acme/accounts"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cminformers "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	cmacmelisters "github.com/cert-manager/cert-manager/pkg/client/listers/acme/v1"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/scheduler"
)

var keyFunc = controllerpkg.KeyFunc

type controller struct {
	// issuer helper is used to obtain references to issuers, used by Sync()
	helper issuer.Helper

	// used to fetch ACME clients used in the controller
	accountRegistry accounts.Getter

	// all the listers used by this controller
	orderLister         cmacmelisters.OrderLister
	challengeLister     cmacmelisters.ChallengeLister
	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
	secretLister        corelisters.SecretLister

	// used for testing
	clock clock.Clock
	// used to record Events about resources to the API
	recorder record.EventRecorder
	// clientset used to update cert-manager API resources
	cmClient cmclient.Interface

	// fieldManager is the manager name used for the Apply operations on Secrets.
	fieldManager string

	// maintain a reference to the workqueue for this controller
	// so the handleOwnedResource method can enqueue resources
	queue workqueue.RateLimitingInterface

	// scheduledWorkQueue holds items to be re-queued after a period of time.
	scheduledWorkQueue scheduler.ScheduledWorkQueue

	// logger to be used by this controller
	log logr.Logger
}

// NewController constructs an orders controller using the provided options.
func NewController(
	log logr.Logger,
	cmClient cmclient.Interface,
	kubeInformerFactory informers.SharedInformerFactory,
	cmInformerFactory cminformers.SharedInformerFactory,
	accountRegistry accounts.Getter,
	recorder record.EventRecorder,
	clock clock.Clock,
	isNamespaced bool,
	fieldManager string,
) (*controller, workqueue.RateLimitingInterface, []cache.InformerSynced) {

	// Create a queue used to queue up Orders to be processed.
	queue := workqueue.NewNamedRateLimitingQueue(
		workqueue.NewItemExponentialFailureRateLimiter(time.Second*5, time.Minute*30),
		ControllerName,
	)

	// Create a scheduledWorkQueue to schedule Orders for re-processing.
	scheduledWorkQueue := scheduler.NewScheduledWorkQueue(clock, queue.Add)

	// Obtain references to all the informers used by this controller.
	orderInformer := cmInformerFactory.Acme().V1().Orders()
	issuerInformer := cmInformerFactory.Certmanager().V1().Issuers()
	challengeInformer := cmInformerFactory.Acme().V1().Challenges()
	secretInformer := kubeInformerFactory.Core().V1().Secrets()

	// Build a list of InformerSynced functions. The controller will only begin
	// processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		orderInformer.Informer().HasSynced,
		issuerInformer.Informer().HasSynced,
		challengeInformer.Informer().HasSynced,
		secretInformer.Informer().HasSynced,
	}

	// Build all the listers.
	orderLister := orderInformer.Lister()
	issuerLister := issuerInformer.Lister()
	challengeLister := challengeInformer.Lister()
	secretLister := secretInformer.Lister()

	// If we are running in non-namespaced mode, we also
	// register event handlers and obtain a lister for ClusterIssuers.
	var clusterIssuerLister cmlisters.ClusterIssuerLister
	if !isNamespaced {
		clusterIssuerInformer := cmInformerFactory.Certmanager().V1().ClusterIssuers()
		mustSync = append(mustSync, clusterIssuerInformer.Informer().HasSynced)
		clusterIssuerLister = clusterIssuerInformer.Lister()
		// register handler function for clusterissuer resources
		clusterIssuerInformer.Informer().AddEventHandler(
			&controllerpkg.BlockingEventHandler{WorkFunc: handleGenericIssuerFunc(queue, orderLister)},
		)
	}

	// register handler functions
	orderInformer.Informer().AddEventHandler(
		&controllerpkg.QueuingEventHandler{Queue: queue},
	)
	issuerInformer.Informer().AddEventHandler(
		&controllerpkg.BlockingEventHandler{WorkFunc: handleGenericIssuerFunc(queue, orderLister)},
	)
	challengeInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		WorkFunc: controllerpkg.HandleOwnedResourceNamespacedFunc(log, queue, orderGvk, orderGetterFunc(orderLister)),
	})

	return &controller{
		clock:               clock,
		queue:               queue,
		scheduledWorkQueue:  scheduledWorkQueue,
		orderLister:         orderLister,
		issuerLister:        issuerLister,
		challengeLister:     challengeLister,
		secretLister:        secretLister,
		clusterIssuerLister: clusterIssuerLister,
		helper:              issuer.NewHelper(issuerLister, clusterIssuerLister),
		recorder:            recorder,
		cmClient:            cmClient,
		accountRegistry:     accountRegistry,
		fieldManager:        fieldManager,
	}, queue, mustSync

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

// Returns a function that finds a named Order in a particular namespace.
func orderGetterFunc(orderLister cmacmelisters.OrderLister) func(string, string) (interface{}, error) {
	return func(namespace, name string) (interface{}, error) {
		return orderLister.Orders(namespace).Get(name)
	}
}

const (
	// ControllerName is the name of the orders controller.
	ControllerName = "orders"
)

// controllerWrapper wraps the `controller` structure to make it implement the
// controllerpkg.queueingController interface. This allows for easier
// instantiation of this controller in integration tests.
type controllerWrapper struct {
	*controller
}

// Register registers a controller, created using the provided context.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
func (c *controllerWrapper) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	// Construct a new named logger to be reused throughout the controller.
	log := logf.FromContext(ctx.RootContext, ControllerName)

	// If --namespace flag was set thus limiting cert-manager to a single namespace.
	isNamespaced := ctx.Namespace != ""

	ctrl, queue, mustSync := NewController(
		log,
		ctx.CMClient,
		ctx.KubeSharedInformerFactory,
		ctx.SharedInformerFactory,
		ctx.ACMEOptions.AccountRegistry,
		ctx.Recorder,
		ctx.Clock,
		isNamespaced,
		ctx.FieldManager,
	)
	c.controller = ctrl

	return queue, mustSync, nil
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&controllerWrapper{}).
			Complete()
	})
}
