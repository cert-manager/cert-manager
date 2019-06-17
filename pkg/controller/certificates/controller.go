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

package certificates

import (
	"context"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/clock"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/pkg/scheduler"
)

type Controller struct {
	*controllerpkg.BaseController

	helper        issuer.Helper
	issuerFactory issuer.IssuerFactory

	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
	certificateLister   cmlisters.CertificateLister
	secretLister        corelisters.SecretLister

	scheduledWorkQueue scheduler.ScheduledWorkQueue
	metrics            *metrics.Metrics

	// used for testing
	clock clock.Clock

	// localTemporarySigner signs a certificate that is stored temporarily
	localTemporarySigner func(crt *v1alpha1.Certificate, pk []byte) ([]byte, error)
}

// New returns a new Certificates controller. It sets up the informer handler
// functions for all the types it watches.
func New(ctx *controllerpkg.Context) *Controller {
	ctrl := &Controller{}
	bctrl := controllerpkg.New(ctx, ControllerName, ctrl.processNextWorkItem)

	certificateInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Certificates()
	bctrl.AddQueuing(controllerpkg.DefaultItemBasedRateLimiter(), "certificates", certificateInformer.Informer())
	ctrl.certificateLister = certificateInformer.Lister()

	// Create a scheduled work queue that calls the ctrl.queue.Add method for
	// each object in the queue. This is used to schedule re-checks of
	// Certificate resources when they get near to expiry
	ctrl.scheduledWorkQueue = scheduler.NewScheduledWorkQueue(bctrl.Queue.AddRateLimited)

	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Issuers()
	bctrl.AddHandled(issuerInformer.Informer(), &controllerpkg.BlockingEventHandler{WorkFunc: ctrl.handleGenericIssuer})
	ctrl.issuerLister = issuerInformer.Lister()

	// if scoped to a single namespace
	if ctx.Namespace == "" {
		clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers()
		bctrl.AddHandled(clusterIssuerInformer.Informer(), &controllerpkg.BlockingEventHandler{WorkFunc: ctrl.handleGenericIssuer})
		ctrl.clusterIssuerLister = clusterIssuerInformer.Lister()
	}

	secretsInformer := ctx.KubeSharedInformerFactory.Core().V1().Secrets()
	bctrl.AddHandled(secretsInformer.Informer(), &controllerpkg.BlockingEventHandler{WorkFunc: ctrl.handleSecretResource})
	ctrl.secretLister = secretsInformer.Lister()

	ordersInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Orders()
	bctrl.AddHandled(ordersInformer.Informer(), &controllerpkg.BlockingEventHandler{WorkFunc: ctrl.handleOwnedResource})

	ctrl.BaseController = bctrl
	ctrl.helper = issuer.NewHelper(ctrl.issuerLister, ctrl.clusterIssuerLister)
	ctrl.metrics = metrics.Default
	ctrl.helper = issuer.NewHelper(ctrl.issuerLister, ctrl.clusterIssuerLister)
	ctrl.issuerFactory = issuer.NewIssuerFactory(ctx)
	ctrl.clock = clock.RealClock{}
	ctrl.localTemporarySigner = generateLocallySignedTemporaryCertificate

	return ctrl
}

func (c *Controller) processNextWorkItem(ctx context.Context, key string) error {
	log := logf.FromContext(ctx)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "invalid resource key")
		return nil
	}

	crt, err := c.certificateLister.Certificates(namespace).Get(name)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			c.scheduledWorkQueue.Forget(key)
			log.Error(err, "certificate in work queue no longer exists")
			return nil
		}

		return err
	}

	ctx = logf.NewContext(ctx, logf.WithResource(log, crt))
	return c.Sync(ctx, crt)
}

var keyFunc = controllerpkg.KeyFunc

const (
	ControllerName = "certificates"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return New(ctx).Run, nil
	})
}
