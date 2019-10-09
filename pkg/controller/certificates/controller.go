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

	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha2"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/scheduler"
)

// certificateRequestManager manages CertificateRequest resources for a
// Certificate in order to obtain signed certs.
type certificateRequestManager struct {
	certificateLister        cmlisters.CertificateLister
	secretLister             corelisters.SecretLister
	certificateRequestLister cmlisters.CertificateRequestLister

	kubeClient kubernetes.Interface
	cmClient   cmclient.Interface

	// maintain a reference to the workqueue for this controller
	// so the handleOwnedResource method can enqueue resources
	queue              workqueue.RateLimitingInterface
	scheduledWorkQueue scheduler.ScheduledWorkQueue

	// used to record Events about resources to the API
	recorder record.EventRecorder

	// used for testing
	clock clock.Clock

	// defined as a field to make it easy to stub out for testing purposes
	generatePrivateKeyBytes generatePrivateKeyBytesFn
	generateCSR             generateCSRFn

	// certificateNeedsRenew is a function that can be used to determine whether
	// a certificate currently requires renewal.
	// This is a field on the controller struct to avoid having to maintain a reference
	// to the controller context, and to make it easier to fake out this call during tests.
	certificateNeedsRenew func(ctx context.Context, cert *x509.Certificate, crt *cmapi.Certificate) bool

	// calculateDurationUntilRenew returns the amount of time before the controller should
	// begin attempting to renew the certificate, given the provided existing certificate
	// and certificate spec.
	// This is a field on the controller struct to avoid having to maintain a reference
	// to the controller context, and to make it easier to fake out this call during tests.
	calculateDurationUntilRenew calculateDurationUntilRenewFn

	// localTemporarySigner signs a certificate that is stored temporarily
	localTemporarySigner localTemporarySignerFn

	// if true, Secret resources created by the controller will have an
	// 'owner reference' set, meaning when the Certificate is deleted, the
	// Secret resource will be automatically deleted.
	// This option is disabled by default.
	enableSecretOwnerReferences bool
}

type localTemporarySignerFn func(crt *cmapi.Certificate, pk []byte) ([]byte, error)

// Register registers and constructs the controller using the provided context.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
func (c *certificateRequestManager) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, []controllerpkg.RunFunc, error) {
	// construct a new named logger to be reused throughout the controller
	log := logf.FromContext(ctx.RootContext, ControllerName)

	// create a queue used to queue up items to be processed
	c.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*5, time.Minute*30), ControllerName)

	// obtain references to all the informers used by this controller
	certificateInformer := ctx.SharedInformerFactory.Certmanager().V1alpha2().Certificates()
	certificateRequestInformer := ctx.SharedInformerFactory.Certmanager().V1alpha2().CertificateRequests()
	secretsInformer := ctx.KubeSharedInformerFactory.Core().V1().Secrets()

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		certificateRequestInformer.Informer().HasSynced,
		secretsInformer.Informer().HasSynced,
		certificateInformer.Informer().HasSynced,
	}

	// set all the references to the listers for used by the Sync function
	c.certificateRequestLister = certificateRequestInformer.Lister()
	c.secretLister = secretsInformer.Lister()
	c.certificateLister = certificateInformer.Lister()

	// register handler functions
	certificateInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue})
	certificateRequestInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: controllerpkg.HandleOwnedResourceNamespacedFunc(log, c.queue, certificateGvk, certificateGetter(c.certificateLister))})
	secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: secretResourceHandler(log, c.certificateLister, c.queue)})

	// Create a scheduled work queue that calls the ctrl.queue.Add method for
	// each object in the queue. This is used to schedule re-checks of
	// Certificate resources when they get near to expiry
	c.scheduledWorkQueue = scheduler.NewScheduledWorkQueue(c.queue.Add)

	// clock is used to determine whether certificates need renewal
	c.clock = clock.RealClock{}

	// recorder records events about resources to the Kubernetes api
	c.recorder = ctx.Recorder

	c.certificateNeedsRenew = ctx.IssuerOptions.CertificateNeedsRenew
	c.calculateDurationUntilRenew = ctx.IssuerOptions.CalculateDurationUntilRenew
	c.generatePrivateKeyBytes = generatePrivateKeyBytesImpl
	c.generateCSR = generateCSRImpl
	// the localTemporarySigner is used to sign 'temporary certificates' during
	// asynchronous certificate issuance flows
	c.localTemporarySigner = generateLocallySignedTemporaryCertificate
	c.enableSecretOwnerReferences = ctx.CertificateOptions.EnableOwnerRef

	c.cmClient = ctx.CMClient
	c.kubeClient = ctx.Client

	return c.queue, mustSync, nil, nil
}

const (
	ControllerName = "certificates"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&certificateRequestManager{}).
			Complete()
	})
}
