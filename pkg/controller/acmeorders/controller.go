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

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	"github.com/jetstack/cert-manager/pkg/acme"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

type Controller struct {
	*controllerpkg.BaseController

	helper     issuer.Helper
	acmeHelper acme.Helper

	orderLister         cmlisters.OrderLister
	challengeLister     cmlisters.ChallengeLister
	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
	secretLister        corelisters.SecretLister

	// used for testing
	clock clock.Clock
}

func New(ctx *controllerpkg.Context) *Controller {
	ctrl := &Controller{}
	bctrl := controllerpkg.New(ctx, ControllerName, ctrl.processNextWorkItem)

	orderInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Orders()
	bctrl.AddQueuing(workqueue.NewItemExponentialFailureRateLimiter(time.Second*5, time.Minute*30), "orders", orderInformer.Informer())
	ctrl.orderLister = orderInformer.Lister()

	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Issuers()
	bctrl.AddHandled(issuerInformer.Informer(), &controllerpkg.BlockingEventHandler{WorkFunc: ctrl.handleGenericIssuer})
	ctrl.issuerLister = issuerInformer.Lister()

	if ctx.Namespace == "" {
		clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers()
		bctrl.AddHandled(clusterIssuerInformer.Informer(), &controllerpkg.BlockingEventHandler{WorkFunc: ctrl.handleGenericIssuer})
		ctrl.clusterIssuerLister = clusterIssuerInformer.Lister()
	}

	challengeInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Challenges()
	bctrl.AddHandled(challengeInformer.Informer(), &controllerpkg.BlockingEventHandler{WorkFunc: ctrl.handleOwnedResource})
	ctrl.challengeLister = challengeInformer.Lister()

	// TODO: detect changes to secrets referenced by order's issuers.
	secretInformer := ctx.KubeSharedInformerFactory.Core().V1().Secrets()
	bctrl.AddWatched(secretInformer.Informer())
	ctrl.secretLister = secretInformer.Lister()

	ctrl.BaseController = bctrl
	ctrl.helper = issuer.NewHelper(ctrl.issuerLister, ctrl.clusterIssuerLister)
	ctrl.acmeHelper = acme.NewHelper(ctrl.secretLister, ctrl.BaseController.Context.ClusterResourceNamespace)
	ctrl.clock = clock.RealClock{}

	return ctrl
}

func (c *Controller) handleOwnedResource(obj interface{}) {
	log := logf.FromContext(c.BaseController.Ctx, "handleOwnedResource")

	metaobj, ok := obj.(metav1.Object)
	if !ok {
		log.Error(nil, "item passed to handleOwnedResource does not implement metav1.Object")
		return
	}
	log = logf.WithResource(log, metaobj)

	ownerRefs := metaobj.GetOwnerReferences()
	for _, ref := range ownerRefs {
		log := log.WithValues(
			logf.RelatedResourceNamespaceKey, metaobj.GetNamespace(),
			logf.RelatedResourceNameKey, ref.Name,
			logf.RelatedResourceKindKey, ref.Kind,
		)

		// Parse the Group out of the OwnerReference to compare it to what was parsed out of the requested OwnerType
		refGV, err := schema.ParseGroupVersion(ref.APIVersion)
		if err != nil {
			log.Error(err, "could not parse OwnerReference GroupVersion")
			continue
		}

		if refGV.Group == orderGvk.Group && ref.Kind == orderGvk.Kind {
			// TODO: how to handle namespace of owner references?
			order, err := c.orderLister.Orders(metaobj.GetNamespace()).Get(ref.Name)
			if err != nil {
				log.Error(err, "error getting order referenced by resource")
				continue
			}
			objKey, err := keyFunc(order)
			if err != nil {
				log.Error(err, "error computing key for resource")
				continue
			}
			c.BaseController.Queue.Add(objKey)
		}
	}
}

func (c *Controller) processNextWorkItem(ctx context.Context, key string) error {
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
		return New(ctx).BaseController.Run, nil
	})
}
