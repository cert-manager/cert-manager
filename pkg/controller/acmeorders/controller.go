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
	"fmt"

	"github.com/go-logr/logr"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	"github.com/cert-manager/cert-manager/pkg/acme/accounts"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cmacmelisters "github.com/cert-manager/cert-manager/pkg/client/listers/acme/v1"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/scheduler"
)

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
	secretLister        internalinformers.SecretLister

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
	queue workqueue.TypedRateLimitingInterface[types.NamespacedName]

	// scheduledWorkQueue holds items to be re-queued after a period of time.
	scheduledWorkQueue scheduler.ScheduledWorkQueue[types.NamespacedName]
}

// NewController constructs an orders controller using the provided options.
func NewController(
	log logr.Logger,
	ctx *controllerpkg.Context,
	isNamespaced bool,
) (*controller, workqueue.TypedRateLimitingInterface[types.NamespacedName], []cache.InformerSynced, error) {

	// Create a queue used to queue up Orders to be processed.
	queue := workqueue.NewTypedRateLimitingQueueWithConfig(
		controllerpkg.DefaultACMERateLimiter(),
		workqueue.TypedRateLimitingQueueConfig[types.NamespacedName]{
			Name: ControllerName,
		},
	)

	// Create a scheduledWorkQueue to schedule Orders for re-processing.
	scheduledWorkQueue := scheduler.NewScheduledWorkQueue(ctx.Clock, queue.Add)

	// Obtain references to all the informers used by this controller.
	orderInformer := ctx.SharedInformerFactory.Acme().V1().Orders()
	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1().Issuers()
	challengeInformer := ctx.SharedInformerFactory.Acme().V1().Challenges()
	secretInformer := ctx.KubeSharedInformerFactory.Secrets()

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
		clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1().ClusterIssuers()
		mustSync = append(mustSync, clusterIssuerInformer.Informer().HasSynced)
		clusterIssuerLister = clusterIssuerInformer.Lister()
		// register handler function for clusterissuer resources
		if _, err := clusterIssuerInformer.Informer().AddEventHandler(
			&controllerpkg.BlockingEventHandler{WorkFunc: handleGenericIssuerFunc(queue, orderLister)},
		); err != nil {
			return nil, nil, nil, fmt.Errorf("error setting up event handler: %v", err)
		}
	}

	// register handler functions
	if _, err := orderInformer.Informer().AddEventHandler(
		&controllerpkg.QueuingEventHandler{Queue: queue},
	); err != nil {
		return nil, nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}
	if _, err := issuerInformer.Informer().AddEventHandler(
		&controllerpkg.BlockingEventHandler{WorkFunc: handleGenericIssuerFunc(queue, orderLister)},
	); err != nil {
		return nil, nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}
	if _, err := challengeInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		WorkFunc: controllerpkg.HandleOwnedResourceNamespacedFunc(log, queue, orderGvk, orderGetterFunc(orderLister)),
	}); err != nil {
		return nil, nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}

	return &controller{
		clock:               ctx.Clock,
		queue:               queue,
		scheduledWorkQueue:  scheduledWorkQueue,
		orderLister:         orderLister,
		issuerLister:        issuerLister,
		challengeLister:     challengeLister,
		secretLister:        secretLister,
		clusterIssuerLister: clusterIssuerLister,
		helper:              issuer.NewHelper(issuerLister, clusterIssuerLister),
		recorder:            ctx.Recorder,
		cmClient:            ctx.CMClient,
		accountRegistry:     ctx.AccountRegistry,
		fieldManager:        ctx.FieldManager,
	}, queue, mustSync, nil

}

func (c *controller) ProcessItem(ctx context.Context, key types.NamespacedName) error {
	log := logf.FromContext(ctx)
	namespace, name := key.Namespace, key.Name

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
func orderGetterFunc(orderLister cmacmelisters.OrderLister) func(string, string) (*cmacme.Order, error) {
	return func(namespace, name string) (*cmacme.Order, error) {
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
func (c *controllerWrapper) Register(ctx *controllerpkg.Context) (workqueue.TypedRateLimitingInterface[types.NamespacedName], []cache.InformerSynced, error) {
	// Construct a new named logger to be reused throughout the controller.
	log := logf.FromContext(ctx.RootContext, ControllerName)

	// If --namespace flag was set thus limiting cert-manager to a single namespace.
	isNamespaced := ctx.Namespace != ""

	ctrl, queue, mustSync, err := NewController(
		log,
		ctx,
		isNamespaced,
	)
	c.controller = ctrl

	return queue, mustSync, err
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&controllerWrapper{}).
			Complete()
	})
}
