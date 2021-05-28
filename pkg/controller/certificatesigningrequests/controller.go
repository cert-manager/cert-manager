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

package certificatesigningrequests

import (
	"context"

	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	authzclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1"
	certificateslisters "k8s.io/client-go/listers/certificates/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

const (
	ControllerName = "certificatesigningrequests"
)

var keyFunc = controllerpkg.KeyFunc

// Signer is an implementation of a Kubernetes CertificateSigningRequest
// signer, backed by a cert-manager Issuer.
type Signer interface {
	Sign(context.Context, *certificatesv1.CertificateSigningRequest, cmapi.GenericIssuer) error
}

// Controller is a base Kubernetes CertificateSigningRequest controller. It is
// responsible for orchestrating and performing shared operations that all
// CertificateSigningRequest controllers do, before passing the
// CertificateSigningRequest to a Singer implementation who instantiated this
// controller.
type Controller struct {
	helper issuer.Helper

	// clientset used to update CertificateSigningRequest API resources
	certClient certificatesclient.CertificateSigningRequestInterface
	csrLister  certificateslisters.CertificateSigningRequestLister
	sarClient  authzclient.SubjectAccessReviewInterface

	queue workqueue.RateLimitingInterface

	// logger to be used by this controller
	log logr.Logger

	// used to record Events about resources to the API
	recorder record.EventRecorder

	// Signer to call sign function
	signer Signer

	// the signer kind to react to when a certificate signing request is synced
	signerType string

	// used for testing
	clock clock.Clock
}

func New(signerType string, signer Signer) *Controller {
	return &Controller{
		signerType: signerType,
		signer:     signer,
	}
}

func (c *Controller) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	c.log = logf.FromContext(ctx.RootContext, ControllerName)

	// create a queue used to queue up items to be processed
	c.queue = workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), ControllerName)

	c.sarClient = ctx.Client.AuthorizationV1().SubjectAccessReviews()

	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1().Issuers()

	// obtain references to all the informers used by this controller
	csrInformer := ctx.KubeSharedInformerFactory.Certificates().V1().CertificateSigningRequests()

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		csrInformer.Informer().HasSynced,
		issuerInformer.Informer().HasSynced,
	}

	// if scoped to a single namespace
	// if we are running in non-namespaced mode (i.e. --namespace=""), we also
	// register event handlers and obtain a lister for clusterissuers.
	clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1().ClusterIssuers()
	if ctx.Namespace == "" {
		// register handler function for clusterissuer resources
		clusterIssuerInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.handleGenericIssuer})
		mustSync = append(mustSync, clusterIssuerInformer.Informer().HasSynced)
	}

	// set all the references to the listers for used by the Sync function
	c.csrLister = csrInformer.Lister()

	// register handler functions
	csrInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue})
	issuerInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.handleGenericIssuer})

	// create an issuer helper for reading generic issuers
	c.helper = issuer.NewHelper(issuerInformer.Lister(), clusterIssuerInformer.Lister())

	c.clock = ctx.Clock
	// recorder records events about resources to the Kubernetes api
	c.recorder = ctx.Recorder
	c.certClient = ctx.Client.CertificatesV1().CertificateSigningRequests()

	c.log.V(logf.DebugLevel).Info("new certificate signing request controller registered",
		"type", c.signerType)

	return c.queue, mustSync, nil
}

func (c *Controller) ProcessItem(ctx context.Context, key string) error {
	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "invalid resource key")
		return nil
	}

	csr, err := c.csrLister.Get(name)
	if apierrors.IsNotFound(err) {
		dbg.Info("certificate signing request in work queue no longer exists", "error", err.Error())
		return nil
	}

	if err != nil {
		return err
	}

	ctx = logf.NewContext(ctx, logf.WithResource(log, csr))
	return c.Sync(ctx, csr)
}
