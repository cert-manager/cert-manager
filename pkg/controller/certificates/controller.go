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
	"crypto/x509"
	"time"

	"github.com/go-logr/logr"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/pkg/scheduler"
)

type controller struct {
	helper        issuer.Helper
	issuerFactory issuer.IssuerFactory

	// clientset used to update cert-manager API resources
	cmClient cmclient.Interface
	kClient  kubernetes.Interface

	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
	certificateLister   cmlisters.CertificateLister
	secretLister        corelisters.SecretLister

	scheduledWorkQueue scheduler.ScheduledWorkQueue
	metrics            *metrics.Metrics

	// used for testing
	clock clock.Clock

	// used to record Events about resources to the API
	recorder record.EventRecorder

	// maintain a reference to the workqueue for this controller
	// so the handleOwnedResource method can enqueue resources
	queue workqueue.RateLimitingInterface

	// logger to be used by this controller
	log logr.Logger

	// localTemporarySigner signs a certificate that is stored temporarily
	localTemporarySigner func(crt *v1alpha1.Certificate, pk []byte) ([]byte, error)

	// certificateNeedsRenew is a function that can be used to determine whether
	// a certificate currently requires renewal.
	// This is a field on the controller struct to avoid having to maintain a reference
	// to the controller context, and to make it easier to fake out this call during tests.
	certificateNeedsRenew func(ctx context.Context, cert *x509.Certificate, crt *v1alpha1.Certificate) bool

	// calculateDurationUntilRenew returns the amount of time before the controller should
	// begin attempting to renew the certificate, given the provided existing certificate
	// and certificate spec.
	// This is a field on the controller struct to avoid having to maintain a reference
	// to the controller context, and to make it easier to fake out this call during tests.
	calculateDurationUntilRenew calculateDurationUntilRenewFn

	// if addOwnerReferences is enabled then the controller will add owner references
	// to the secret resources it creates
	addOwnerReferences bool
}

type calculateDurationUntilRenewFn func(context.Context, *x509.Certificate, *v1alpha1.Certificate) time.Duration

// Register registers and constructs the controller using the provided context.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
func (c *controller) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	c.log = logf.FromContext(ctx.RootContext, ControllerName)

	// create a queue used to queue up items to be processed
	c.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*5, time.Minute*30), ControllerName)

	// obtain references to all the informers used by this controller
	certificateInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Certificates()
	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Issuers()
	secretsInformer := ctx.KubeSharedInformerFactory.Core().V1().Secrets()
	ordersInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Orders()

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		certificateInformer.Informer().HasSynced,
		issuerInformer.Informer().HasSynced,
		secretsInformer.Informer().HasSynced,
		ordersInformer.Informer().HasSynced,
	}

	// set all the references to the listers for used by the Sync function
	c.certificateLister = certificateInformer.Lister()
	c.issuerLister = issuerInformer.Lister()
	c.secretLister = secretsInformer.Lister()

	// if scoped to a single namespace
	// if we are running in non-namespaced mode (i.e. --namespace=""), we also
	// register event handlers and obtain a lister for clusterissuers.
	if ctx.Namespace == "" {
		clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers()
		c.clusterIssuerLister = clusterIssuerInformer.Lister()
		// register handler function for clusterissuer resources
		clusterIssuerInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.handleGenericIssuer})
		mustSync = append(mustSync, clusterIssuerInformer.Informer().HasSynced)
	}

	// register handler functions
	certificateInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue})
	issuerInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.handleGenericIssuer})
	secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: secretResourceHandler(c.log, c.certificateLister, c.queue)})
	ordersInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		WorkFunc: controllerpkg.HandleOwnedResourceNamespacedFunc(c.log, c.queue, certificateGvk, certificateGetter(c.certificateLister)),
	})

	// Create a scheduled work queue that calls the ctrl.queue.Add method for
	// each object in the queue. This is used to schedule re-checks of
	// Certificate resources when they get near to expiry
	c.scheduledWorkQueue = scheduler.NewScheduledWorkQueue(c.queue.AddRateLimited)

	// instantiate metrics interface with default metrics implementation
	c.metrics = metrics.Default
	// configure the metrics package to use the certificate lister for detecting
	// 'removed' certificates and cleaning up metrics
	// TODO: this call should be moved to somewhere more generic/global than this
	// controller, as the metrics package is used by more than this one controller.
	c.metrics.SetActiveCertificates(c.certificateLister)

	// create an issuer helper for reading generic issuers
	c.helper = issuer.NewHelper(c.issuerLister, c.clusterIssuerLister)
	// issuerFactory provides an interface to obtain Issuer implementations from issuer resources
	c.issuerFactory = issuer.NewIssuerFactory(ctx)
	// clock is used to determine whether certificates need renewal
	c.clock = clock.RealClock{}
	// recorder records events about resources to the Kubernetes api
	c.recorder = ctx.Recorder
	// the localTemporarySigner is used to sign 'temporary certificates' during
	// asynchronous certificate issuance flows
	c.localTemporarySigner = generateLocallySignedTemporaryCertificate
	// use the controller context provided versions of these two methods
	c.certificateNeedsRenew = ctx.IssuerOptions.CertificateNeedsRenew
	c.calculateDurationUntilRenew = ctx.IssuerOptions.CalculateDurationUntilRenew
	c.cmClient = ctx.CMClient
	c.kClient = ctx.Client
	c.addOwnerReferences = ctx.CertificateOptions.EnableOwnerRef

	return c.queue, mustSync, nil
}

func (c *controller) ProcessItem(ctx context.Context, key string) error {
	ctx = logf.NewContext(ctx, nil, ControllerName)
	log := logf.FromContext(ctx)

	crt, err := getCertificateForKey(ctx, key, c.certificateLister)
	if k8sErrors.IsNotFound(err) {
		log.Error(err, "certificate resource not found for key", "key", key)
		return nil
	}
	if crt == nil {
		log.Info("certificate resource not found for key", "key", key)
		return nil
	}
	if err != nil {
		return err
	}

	return c.Sync(ctx, crt)
}

type syncFn func(context.Context, *v1alpha1.Certificate) error

func getCertificateForKey(ctx context.Context, key string, lister cmlisters.CertificateLister) (*v1alpha1.Certificate, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, nil
	}

	crt, err := lister.Certificates(namespace).Get(name)
	if k8sErrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return crt, nil
}

func certificateGetter(lister cmlisters.CertificateLister) func(namespace, name string) (interface{}, error) {
	return func(namespace, name string) (interface{}, error) {
		return lister.Certificates(namespace).Get(name)
	}
}

var keyFunc = controllerpkg.KeyFunc

const (
	ControllerName = "certificates"
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
