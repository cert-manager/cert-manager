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

package issuing

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cminformers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificates"
	"github.com/jetstack/cert-manager/pkg/controller/certificates/internal/secretsmanager"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	utilkube "github.com/jetstack/cert-manager/pkg/util/kube"
	utilpki "github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/pkg/util/predicate"
)

const (
	ControllerName = "CertificateIssuing"
)

type localTemporarySignerFn func(crt *cmapi.Certificate, pk []byte) ([]byte, error)

// This controller observes the state of the certificate's 'Issuing' condition,
// which will then copy the signed certificates and private key to the target
// Secret resource.
type controller struct {
	certificateLister        cmlisters.CertificateLister
	certificateRequestLister cmlisters.CertificateRequestLister
	secretLister             corelisters.SecretLister
	recorder                 record.EventRecorder
	clock                    clock.Clock

	client cmclient.Interface

	// secretManager is used to create and update Secrets with certificate and key data
	secretsManager *secretsmanager.SecretsManager
	// localTemporarySigner signs a certificate that is stored temporarily
	localTemporarySigner localTemporarySignerFn
}

func NewController(
	log logr.Logger,
	kubeClient kubernetes.Interface,
	client cmclient.Interface,
	factory informers.SharedInformerFactory,
	cmFactory cminformers.SharedInformerFactory,
	recorder record.EventRecorder,
	clock clock.Clock,
	certificateControllerOptions controllerpkg.CertificateOptions,
) (*controller, workqueue.RateLimitingInterface, []cache.InformerSynced) {

	// create a queue used to queue up items to be processed
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*1, time.Second*30), ControllerName)

	// obtain references to all the informers used by this controller
	certificateInformer := cmFactory.Certmanager().V1().Certificates()
	certificateRequestInformer := cmFactory.Certmanager().V1().CertificateRequests()
	secretsInformer := factory.Core().V1().Secrets()

	certificateInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: queue})
	certificateRequestInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		WorkFunc: certificates.EnqueueCertificatesForResourceUsingPredicates(log, queue, certificateInformer.Lister(), labels.Everything(), predicate.ResourceOwnerOf),
	})
	secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		// Issuer reconciles on changes to the Secret named `spec.nextPrivateKeySecretName`
		WorkFunc: certificates.EnqueueCertificatesForResourceUsingPredicates(log, queue, certificateInformer.Lister(), labels.Everything(),
			predicate.ResourceOwnerOf,
			predicate.ExtractResourceName(predicate.CertificateNextPrivateKeySecretName)),
	})
	secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		// Issuer reconciles on changes to the Secret named `spec.secretName`
		WorkFunc: certificates.EnqueueCertificatesForResourceUsingPredicates(log, queue, certificateInformer.Lister(), labels.Everything(),
			predicate.ExtractResourceName(predicate.CertificateSecretName)),
	})

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		certificateRequestInformer.Informer().HasSynced,
		secretsInformer.Informer().HasSynced,
		certificateInformer.Informer().HasSynced,
	}

	secretsManager := secretsmanager.New(
		kubeClient,
		secretsInformer.Lister(),
		certificateControllerOptions.EnableOwnerRef,
	)

	return &controller{
		certificateLister:        certificateInformer.Lister(),
		certificateRequestLister: certificateRequestInformer.Lister(),
		secretLister:             secretsInformer.Lister(),
		client:                   client,
		recorder:                 recorder,
		clock:                    clock,
		secretsManager:           secretsManager,
		localTemporarySigner:     certificates.GenerateLocallySignedTemporaryCertificate,
	}, queue, mustSync
}

func (c *controller) ProcessItem(ctx context.Context, key string) error {
	// Set context deadline for full sync in 10 seconds
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	log := logf.FromContext(ctx).WithValues("key", key)

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil
	}

	crt, err := c.certificateLister.Certificates(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		log.Error(err, "certificate not found for key")
		return nil
	}
	if err != nil {
		return err
	}

	log = logf.WithResource(log, crt)
	ctx = logf.NewContext(ctx, log)

	if !apiutil.CertificateHasCondition(crt, cmapi.CertificateCondition{
		Type:   cmapi.CertificateConditionIssuing,
		Status: cmmeta.ConditionTrue,
	}) {
		// Do nothing if an issuance is not in progress.
		return nil
	}

	if crt.Status.NextPrivateKeySecretName == nil ||
		len(*crt.Status.NextPrivateKeySecretName) == 0 {
		// Do nothing if the next private key secret name is not set
		return nil
	}

	// Fetch and parse the 'next private key secret'
	nextPrivateKeySecret, err := c.secretLister.Secrets(crt.Namespace).Get(*crt.Status.NextPrivateKeySecretName)
	if apierrors.IsNotFound(err) {
		log.V(logf.DebugLevel).Info("Next private key secret does not exist, waiting for keymanager controller")
		// If secret does not exist, do nothing (keymanager will handle this).
		return nil
	}
	if err != nil {
		return err
	}
	if nextPrivateKeySecret.Data == nil || len(nextPrivateKeySecret.Data[corev1.TLSPrivateKeyKey]) == 0 {
		logf.WithResource(log, nextPrivateKeySecret).Info("Next private key secret does not contain any private key data, waiting for keymanager controller")
		return nil
	}
	pk, _, err := utilkube.ParseTLSKeyFromSecret(nextPrivateKeySecret, corev1.TLSPrivateKeyKey)
	if err != nil {
		// If the private key cannot be parsed here, do nothing as the key manager will handle this.
		logf.WithResource(log, nextPrivateKeySecret).Error(err, "failed to parse next private key, waiting for keymanager controller")
		return nil
	}
	pkViolations, err := certificates.PrivateKeyMatchesSpec(pk, crt.Spec)
	if err != nil {
		return err
	}
	if len(pkViolations) > 0 {
		logf.WithResource(log, nextPrivateKeySecret).Info("stored next private key does not match requirements on Certificate resource, waiting for keymanager controller", "violations", pkViolations)
		return nil
	}

	// CertificateRequest revisions begin from 1. If no revision is set on the
	// status then assume no revision yet set.
	nextRevision := 1
	if crt.Status.Revision != nil {
		nextRevision = *crt.Status.Revision + 1
	}

	reqs, err := certificates.ListCertificateRequestsMatchingPredicates(c.certificateRequestLister.CertificateRequests(crt.Namespace),
		labels.Everything(),
		predicate.CertificateRequestRevision(nextRevision),
		predicate.ResourceOwnedBy(crt),
	)
	if err != nil || len(reqs) != 1 {
		// If error return.
		// if no error but none exist do nothing.
		// If no error but multiple exist, then leave to requestmanager controller
		// to clean up.
		return err
	}

	req := reqs[0]
	log = logf.WithResource(log, req)

	// Verify the CSR options match what is requested in certificate.spec.
	// If there are violations in the spec, then the requestmanager will handle this.
	requestViolations, err := certificates.RequestMatchesSpec(req, crt.Spec)
	if err != nil {
		return err
	}
	if len(requestViolations) > 0 {
		log.V(logf.DebugLevel).Info("CertificateRequest does not match Certificate, waiting for keymanager controller")
		return nil
	}

	cond := apiutil.GetCertificateRequestCondition(req, cmapi.CertificateRequestConditionReady)
	if cond == nil {
		log.V(logf.DebugLevel).Info("CertificateRequest does not have Ready condition, waiting...")
		return nil
	}

	// If the certificate request has failed, set the last failure time to now,
	// and set the Issuing status condition to False with reason.
	if cond.Reason == cmapi.CertificateRequestReasonFailed {
		return c.failIssueCertificate(ctx, log, crt, req)
	}

	// If public key does not match, do nothing (requestmanager will handle this).
	csr, err := utilpki.DecodeX509CertificateRequestBytes(req.Spec.Request)
	if err != nil {
		return err
	}
	publicKeyMatchesCSR, err := utilpki.PublicKeyMatchesCSR(pk.Public(), csr)
	if err != nil {
		return err
	}
	if !publicKeyMatchesCSR {
		logf.WithResource(log, nextPrivateKeySecret).Info("next private key does not match CSR public key, waiting for requestmanager controller")
		return nil
	}

	// If the CertificateRequest is valid and ready, verify its status and issue
	// accordingly.
	if cond.Reason == cmapi.CertificateRequestReasonIssued {
		return c.issueCertificate(ctx, nextRevision, crt, req, pk)
	}

	// Issue temporary certificate if needed. If a certificate was issued, then
	// return early - we will sync again since the target Secret has been
	// updated.
	if issued, err := c.ensureTemporaryCertificate(ctx, crt, pk); err != nil || issued {
		return err
	}

	// CertificateRequest is not in a final state so do nothing.
	log.V(logf.DebugLevel).Info("CertificateRequest not in final state, waiting...", "reason", cond.Reason)
	return nil
}

// failIssueCertificate will mark the condition Issuing of this Certificate as failed, and log an appropriate event
func (c *controller) failIssueCertificate(ctx context.Context, log logr.Logger, crt *cmapi.Certificate, req *cmapi.CertificateRequest) error {
	nowTime := metav1.NewTime(c.clock.Now())
	crt.Status.LastFailureTime = &nowTime

	log.V(logf.DebugLevel).Info("CertificateRequest in failed state so retrying issuance later")

	var reason, message string
	condition := apiutil.GetCertificateRequestCondition(req, cmapi.CertificateRequestConditionReady)

	reason = condition.Reason
	message = fmt.Sprintf("The certificate request has failed to complete and will be retried: %s",
		condition.Message)

	crt = crt.DeepCopy()
	apiutil.SetCertificateCondition(crt, cmapi.CertificateConditionIssuing, cmmeta.ConditionFalse, reason, message)

	_, err := c.client.CertmanagerV1().Certificates(crt.Namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	c.recorder.Event(crt, corev1.EventTypeWarning, reason, message)

	return nil
}

// issueCertificate will ensure the public key of the CSR matches the signed
// certificate, and then store the certificate, CA and private key into the
// Secret in the appropriate format type.
func (c *controller) issueCertificate(ctx context.Context, nextRevision int, crt *cmapi.Certificate, req *cmapi.CertificateRequest, pk crypto.Signer) error {
	crt = crt.DeepCopy()
	if crt.Spec.PrivateKey == nil {
		crt.Spec.PrivateKey = &cmapi.CertificatePrivateKey{}
	}

	pkData, err := utilpki.EncodePrivateKey(pk, crt.Spec.PrivateKey.Encoding)
	if err != nil {
		return err
	}
	secretData := secretsmanager.SecretData{
		PrivateKey:  pkData,
		Certificate: req.Status.Certificate,
		CA:          req.Status.CA,
	}

	err = c.secretsManager.UpdateData(ctx, crt, secretData)
	if err != nil {
		return err
	}

	//Set status.revision to revision of the CertificateRequest
	crt.Status.Revision = &nextRevision

	// Remove Issuing status condition
	apiutil.RemoveCertificateCondition(crt, cmapi.CertificateConditionIssuing)

	//Clear status.lastFailureTime (if set)
	crt.Status.LastFailureTime = nil

	_, err = c.client.CertmanagerV1().Certificates(crt.Namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	message := "The certificate has been successfully issued"
	c.recorder.Event(crt, corev1.EventTypeNormal, "Issuing", message)

	return nil
}

// controllerWrapper wraps the `controller` structure to make it implement
// the controllerpkg.queueingController interface
type controllerWrapper struct {
	*controller
}

func (c *controllerWrapper) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	log := logf.FromContext(ctx.RootContext, ControllerName)

	ctrl, queue, mustSync := NewController(log,
		ctx.Client,
		ctx.CMClient,
		ctx.KubeSharedInformerFactory,
		ctx.SharedInformerFactory,
		ctx.Recorder,
		ctx.Clock,
		ctx.CertificateOptions,
	)
	c.controller = ctrl

	return queue, mustSync, nil
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&controllerWrapper{}).
			Complete()
	})
}
