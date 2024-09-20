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
	"fmt"

	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	authzclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1"
	certificateslisters "k8s.io/client-go/listers/certificates/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// Signer is an implementation of a Kubernetes CertificateSigningRequest
// signer, backed by a cert-manager Issuer.
type Signer interface {
	Sign(context.Context, *certificatesv1.CertificateSigningRequest, cmapi.GenericIssuer) error
}

// Signer Contractor builds a Signer instance using the given controller
// context.
type SignerConstructor func(*controllerpkg.Context) Signer

// RegisterExtraInformerFn is a function used by CertificateSigningRequest
// controller implementations to add custom workqueue functions based on
// informers not covered in the main shared controller implementation.
// The returned set of InformerSyncs will be waited on when the controller
// starts.
type RegisterExtraInformerFn func(*controllerpkg.Context, logr.Logger, workqueue.TypedRateLimitingInterface[types.NamespacedName]) ([]cache.InformerSynced, error)

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

	// fieldManager is the manager name used for the Apply operations.
	fieldManager string

	queue workqueue.TypedRateLimitingInterface[types.NamespacedName]

	// logger to be used by this controller
	log logr.Logger

	// used to record Events about resources to the API
	recorder record.EventRecorder

	// Signer to call sign function
	signerConstructor SignerConstructor
	signer            Signer

	// the signer kind to react to when a certificate signing request is synced
	signerType string

	// registerExtraInformers is a list of functions that
	// CertificateSigningRequest controllers can use to register custom informers.
	registerExtraInformers []RegisterExtraInformerFn

	// used for testing
	clock clock.Clock
}

// New will construct a new certificatesigningrequest controller using the
// given Signer implementation.
// Note: the registerExtraInformers passed here will be 'waited' for when
// starting to ensure their corresponding listers have synced.
// The caller is responsible for ensuring the informer work functions are setup
// correctly on any informer.
// It's also the callers responsibility to ensure the Run function on the
// informer is called in order to start the reflector. This is handled
// automatically when the informer factory's Start method is called, if the
// given informer was obtained using a SharedInformerFactory.
func New(signerType string, signerConstructor SignerConstructor, registerExtraInformers ...RegisterExtraInformerFn) *Controller {
	return &Controller{
		signerType:             signerType,
		signerConstructor:      signerConstructor,
		registerExtraInformers: registerExtraInformers,
	}
}

func (c *Controller) Register(ctx *controllerpkg.Context) (workqueue.TypedRateLimitingInterface[types.NamespacedName], []cache.InformerSynced, error) {
	componentName := "certificatesigningrequests-" + c.signerType

	// construct a new named logger to be reused throughout the controller
	c.log = logf.FromContext(ctx.RootContext, componentName)

	// create a queue used to queue up items to be processed
	c.queue = workqueue.NewTypedRateLimitingQueueWithConfig(
		controllerpkg.DefaultItemBasedRateLimiter(),
		workqueue.TypedRateLimitingQueueConfig[types.NamespacedName]{
			Name: componentName,
		},
	)

	kubeClient := ctx.Client
	c.sarClient = kubeClient.AuthorizationV1().SubjectAccessReviews()

	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1().Issuers()

	// obtain references to all the informers used by this controller
	csrInformer := ctx.KubeSharedInformerFactory.CertificateSigningRequests()

	// build a list of InformerSynced functions that will be returned by the
	// Register method. The controller will only begin processing items once all
	// of these informers have synced.

	mustSync := []cache.InformerSynced{
		csrInformer.Informer().HasSynced,
		issuerInformer.Informer().HasSynced,
	}

	for _, reg := range c.registerExtraInformers {
		ms, err := reg(ctx, c.log, c.queue)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to register extra informer: %w", err)
		}
		mustSync = append(mustSync, ms...)
	}

	// if scoped to a single namespace
	// if we are running in non-namespaced mode (i.e. --namespace=""), we also
	// register event handlers and obtain a lister for clusterissuers.
	clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1().ClusterIssuers()
	if ctx.Namespace == "" {
		// register handler function for clusterissuer resources
		if _, err := clusterIssuerInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.handleGenericIssuer}); err != nil {
			return nil, nil, fmt.Errorf("error setting up event handler: %v", err)
		}
		mustSync = append(mustSync, clusterIssuerInformer.Informer().HasSynced)
	}

	// set all the references to the listers for used by the Sync function
	c.csrLister = csrInformer.Lister()

	// register handler functions
	if _, err := csrInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue}); err != nil {
		return nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}
	if _, err := issuerInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.handleGenericIssuer}); err != nil {
		return nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}

	// create an issuer helper for reading generic issuers
	c.helper = issuer.NewHelper(issuerInformer.Lister(), clusterIssuerInformer.Lister())

	c.clock = ctx.Clock
	// recorder records events about resources to the Kubernetes api
	c.recorder = ctx.Recorder
	c.certClient = kubeClient.CertificatesV1().CertificateSigningRequests()
	c.fieldManager = ctx.FieldManager

	// Construct the signer implementation with the built component context.
	c.signer = c.signerConstructor(ctx)

	c.log.V(logf.DebugLevel).Info("new certificate signing request controller registered",
		"type", c.signerType)

	return c.queue, mustSync, nil
}

func (c *Controller) ProcessItem(ctx context.Context, key types.NamespacedName) error {
	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

	name := key.Name

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
