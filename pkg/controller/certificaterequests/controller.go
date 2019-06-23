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

package certificaterequests

import (
	"context"
	"sync"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
)

const (
	ControllerName = "certificaterequests"
)

var keyFunc = controllerpkg.KeyFunc

type Controller struct {
	*controllerpkg.BaseController

	helper        issuer.Helper
	issuerFactory issuer.IssuerFactory

	// To allow injection for testing.
	syncHandler func(ctx context.Context, key string) error

	issuerLister             cmlisters.IssuerLister
	clusterIssuerLister      cmlisters.ClusterIssuerLister
	certificateRequestLister cmlisters.CertificateRequestLister

	queue       workqueue.RateLimitingInterface
	workerWg    sync.WaitGroup
	syncedFuncs []cache.InformerSynced
	metrics     *metrics.Metrics

	// used for testing
	clock clock.Clock
}

// New returns a new CertificateRequests controller. It sets up the informer
// handler functions for all the types it watches.
func New(ctx *controllerpkg.Context) *Controller {
	ctrl := &Controller{}
	bctrl := controllerpkg.New(ctx, ControllerName, ctrl.processNextWorkItem)

	certificateRequestInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().CertificateRequests()
	bctrl.AddQueuing(controllerpkg.DefaultItemBasedRateLimiter(), "certificaterequests", certificateRequestInformer.Informer())
	ctrl.certificateRequestLister = certificateRequestInformer.Lister()

	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Issuers()
	bctrl.AddHandled(issuerInformer.Informer(), &controllerpkg.BlockingEventHandler{WorkFunc: ctrl.handleGenericIssuer})
	ctrl.issuerLister = issuerInformer.Lister()

	// if scoped to a single namespace
	if ctx.Namespace == "" {
		clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers()
		bctrl.AddHandled(clusterIssuerInformer.Informer(), &controllerpkg.BlockingEventHandler{WorkFunc: ctrl.handleGenericIssuer})
		ctrl.clusterIssuerLister = clusterIssuerInformer.Lister()
	}

	ctrl.BaseController = bctrl
	ctrl.helper = issuer.NewHelper(ctrl.issuerLister, ctrl.clusterIssuerLister)
	ctrl.metrics = metrics.Default
	// TODO: set up metrics
	//ctrl.metrics.SetActiveCertificateRequestss(ctrl.certificateLister)
	ctrl.helper = issuer.NewHelper(ctrl.issuerLister, ctrl.clusterIssuerLister)
	ctrl.issuerFactory = issuer.NewIssuerFactory(ctx)
	ctrl.clock = clock.RealClock{}

	return ctrl
}

func (c *Controller) processNextWorkItem(ctx context.Context, key string) error {
	log := logf.FromContext(ctx)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "invalid resource key")
		return nil
	}

	cr, err := c.certificateRequestLister.CertificateRequests(namespace).Get(name)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			log.Error(err, "certificate request in work queue no longer exists")
			return nil
		}

		return err
	}

	ctx = logf.NewContext(ctx, logf.WithResource(log, cr))
	return c.Sync(ctx, cr)
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return New(ctx).Run, nil
	})
}
