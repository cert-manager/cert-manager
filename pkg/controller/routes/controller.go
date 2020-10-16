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

package routes

import (
	"context"
	"time"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"

	routeClient "github.com/openshift/client-go/route/clientset/versioned"
	routeListers "github.com/openshift/client-go/route/listers/route/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/workqueue"

	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

// // certificateRequestManager manages CertificateRequest resources for a
// // Certificate in order to obtain signed certs.
type routeRequestManager struct {
	routeLister  routeListers.RouteLister
	secretLister corelisters.SecretLister
	routeClient  routeClient.Interface
	kubeClient   kubernetes.Interface

	// maintain a reference to the workqueue for this controller
	// so the handleOwnedResource method can enqueue resources
	queue workqueue.RateLimitingInterface

	// used to record Events about resources to the API
	recorder record.EventRecorder

	// used for testing
	clock clock.Clock
}

// Register registers and constructs the controller using the provided context.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
func (c *routeRequestManager) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	log := logf.FromContext(ctx.RootContext, ControllerName)

	// create a queue used to queue up items to be processed
	c.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*5, time.Minute*30), ControllerName)

	// 	// obtain references to all the informers used by this controller
	routeInformer := ctx.OpenShiftRouteInformerFactory.Route()
	secretsInformer := ctx.KubeSharedInformerFactory.Core().V1().Secrets()

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		secretsInformer.Informer().HasSynced,
		routeInformer.V1().Routes().Informer().HasSynced,
	}

	// 	// set all the references to the listers for used by the Sync function
	c.routeLister = routeInformer.V1().Routes().Lister()
	c.secretLister = secretsInformer.Lister()

	// register handler functions
	routeInformer.V1().Routes().Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue})
	secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: secretResourceHandler(log, c.routeLister, c.queue)})

	// clock is used to determine whether certificates need renewal
	c.clock = clock.RealClock{}

	// recorder records events about resources to the Kubernetes api
	c.recorder = ctx.Recorder

	// Setup clients
	c.routeClient = ctx.RouteClient
	c.kubeClient = ctx.Client

	return c.queue, mustSync, nil
}

const (
	ControllerName = "routes"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		if ok, err := IsRouteResourceAvailable(ctx); !ok || err != nil {
			if err != nil {
				return nil, err
			}
			return nil, nil
		}

		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&routeRequestManager{}).
			Complete()
	})
}

func (c *routeRequestManager) ProcessItem(ctx context.Context, key string) error {
	log := logf.FromContext(ctx)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "invalid resource key")
		return nil
	}

	route, err := c.routeLister.Routes(namespace).Get(name)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			log.Error(err, "route in work queue no longer exists")
			return nil
		}

		return err
	}

	ctx = logf.NewContext(ctx, logf.WithResource(log, route))
	return c.Sync(ctx, route)
}
