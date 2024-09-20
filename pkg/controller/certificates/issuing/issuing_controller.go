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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	internalcertificates "github.com/cert-manager/cert-manager/internal/controller/certificates"
	"github.com/cert-manager/cert-manager/internal/controller/certificates/policies"
	"github.com/cert-manager/cert-manager/internal/controller/feature"
	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/issuing/internal"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	utilkube "github.com/cert-manager/cert-manager/pkg/util/kube"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/pkg/util/predicate"
)

const (
	ControllerName = "certificates-issuing"
)

type localTemporarySignerFn func(crt *cmapi.Certificate, pk []byte) ([]byte, error)

// This controller observes the state of the certificate's 'Issuing' condition,
// which will then copy the signed certificates and private key to the target
// Secret resource.
type controller struct {
	certificateLister        cmlisters.CertificateLister
	certificateRequestLister cmlisters.CertificateRequestLister
	secretLister             internalinformers.SecretLister
	recorder                 record.EventRecorder
	clock                    clock.Clock

	client cmclient.Interface

	// secretsUpdateData is used by the SecretTemplate controller for
	// re-reconciling Secrets where the SecretTemplate is not up to date with a
	// Certificate's secret.
	secretsUpdateData func(context.Context, *cmapi.Certificate, internal.SecretData) error

	// postIssuancePolicyChain is the policies chain to ensure that all Secret
	// metadata and output formats are kept are present and correct.
	postIssuancePolicyChain policies.Chain

	// fieldManager is the string which will be used as the Field Manager on
	// fields created or edited by the cert-manager Kubernetes client during
	// Apply API calls.
	fieldManager string

	// localTemporarySigner signs a certificate that is stored temporarily
	localTemporarySigner localTemporarySignerFn
}

func NewController(
	log logr.Logger,
	ctx *controllerpkg.Context,
) (*controller, workqueue.TypedRateLimitingInterface[types.NamespacedName], []cache.InformerSynced, error) {

	// create a queue used to queue up items to be processed
	queue := workqueue.NewTypedRateLimitingQueueWithConfig(
		controllerpkg.DefaultCertificateRateLimiter(),
		workqueue.TypedRateLimitingQueueConfig[types.NamespacedName]{
			Name: ControllerName,
		},
	)

	// obtain references to all the informers used by this controller
	certificateInformer := ctx.SharedInformerFactory.Certmanager().V1().Certificates()
	certificateRequestInformer := ctx.SharedInformerFactory.Certmanager().V1().CertificateRequests()
	secretsInformer := ctx.KubeSharedInformerFactory.Secrets()

	if _, err := certificateInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: queue}); err != nil {
		return nil, nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}
	if _, err := certificateRequestInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		WorkFunc: certificates.EnqueueCertificatesForResourceUsingPredicates(log, queue, certificateInformer.Lister(), labels.Everything(), predicate.ResourceOwnerOf),
	}); err != nil {
		return nil, nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}
	if _, err := secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		// Issuer reconciles on changes to the Secret named `spec.nextPrivateKeySecretName`
		WorkFunc: certificates.EnqueueCertificatesForResourceUsingPredicates(log, queue, certificateInformer.Lister(), labels.Everything(),
			predicate.ResourceOwnerOf,
			predicate.ExtractResourceName(predicate.CertificateNextPrivateKeySecretName)),
	}); err != nil {
		return nil, nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}
	if _, err := secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		// Issuer reconciles on changes to the Secret named `spec.secretName`
		WorkFunc: certificates.EnqueueCertificatesForResourceUsingPredicates(log, queue, certificateInformer.Lister(), labels.Everything(),
			predicate.ExtractResourceName(predicate.CertificateSecretName)),
	}); err != nil {
		return nil, nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		certificateRequestInformer.Informer().HasSynced,
		secretsInformer.Informer().HasSynced,
		certificateInformer.Informer().HasSynced,
	}

	secretsManager := internal.NewSecretsManager(
		ctx.Client.CoreV1(), secretsInformer.Lister(),
		ctx.FieldManager, ctx.CertificateOptions.EnableOwnerRef,
	)

	return &controller{
		certificateLister:        certificateInformer.Lister(),
		certificateRequestLister: certificateRequestInformer.Lister(),
		secretLister:             secretsInformer.Lister(),
		client:                   ctx.CMClient,
		recorder:                 ctx.Recorder,
		clock:                    ctx.Clock,
		secretsUpdateData:        secretsManager.UpdateData,
		postIssuancePolicyChain: policies.NewSecretPostIssuancePolicyChain(
			ctx.CertificateOptions.EnableOwnerRef,
			ctx.FieldManager,
		),
		fieldManager:         ctx.FieldManager,
		localTemporarySigner: pki.GenerateLocallySignedTemporaryCertificate,
	}, queue, mustSync, nil
}

func (c *controller) ProcessItem(ctx context.Context, key types.NamespacedName) error {
	// TODO: Change to globals.DefaultControllerContextTimeout as part of a wider effort to ensure we have
	// failsafe timeouts in every controller
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	log := logf.FromContext(ctx).WithValues("key", key)

	namespace, name := key.Namespace, key.Name

	crt, err := c.certificateLister.Certificates(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		log.V(logf.DebugLevel).Info("certificate not found for key", "error", err.Error())
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
		// If Certificate doesn't have Issuing=true condition then we should check
		// to ensure all non-issuing related SecretData is correct on the
		// Certificate's secret.
		return c.ensureSecretData(ctx, log, crt)
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
	pkViolations := pki.PrivateKeyMatchesSpec(pk, crt.Spec)
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
	requestViolations, err := pki.RequestMatchesSpec(req, crt.Spec)
	if err != nil {
		return err
	}
	if len(requestViolations) > 0 {
		log.V(logf.DebugLevel).Info("CertificateRequest does not match Certificate, waiting for keymanager controller")
		return nil
	}

	certIssuingCond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionIssuing)
	crReadyCond := apiutil.GetCertificateRequestCondition(req, cmapi.CertificateRequestConditionReady)
	if certIssuingCond == nil {
		// This should never happen
		log.V(logf.ErrorLevel).Info("Certificate does not have an issuing condition")
		return nil
	}
	// If the CertificateRequest for this revision failed before the
	// Issuing condition was last updated on the Certificate, then it must be a
	// failed CertificateRequest from the previous issuance for the same
	// revision. Leave it to the certificate-requests controller to delete the
	// CertificateRequest and create a new one.
	if req.Status.FailureTime != nil &&
		req.Status.FailureTime.Before(certIssuingCond.LastTransitionTime) && crReadyCond.Reason == cmapi.CertificateRequestReasonFailed {
		log.V(logf.InfoLevel).Info("Found a failed CertificateRequest from previous issuance, waiting for it to be deleted...")
		return nil
	}

	// Now check if CertificateRequest is in any of the final states so that
	// this issuance can be completed as either succeeded or failed. Failed
	// issuance will be retried with a delay (the logic for that lives in
	// certificates-trigger controller). Final states are: Denied condition
	// with status True => fail issuance InvalidRequest  condition with
	// status True => fail issuance Ready condition with reason Failed =>
	// fail issuance Ready condition with reason Issued => finalize issuance
	// as succeeded.

	// In case of a non-compliant issuer, a CertificateRequest can have both
	// Denied status True (set by an approver) and Ready condition with
	// reason Issued (set by the issuer). In this case, we prioritize the
	// Denied condition and fail the issuance. This is done for consistency
	// and also to avoid race conditions between the non-compliant issuer
	// and this control loop.

	// If the certificate request was denied, set the last failure time to
	// now, bump the issuance attempts and set the Issuing status condition
	// to False.
	if apiutil.CertificateRequestIsDenied(req) {
		return c.failIssueCertificate(ctx, log, crt, apiutil.GetCertificateRequestCondition(req, cmapi.CertificateRequestConditionDenied))
	}

	// If the certificate request is invalid, set the last failure time to
	// now, bump the issuance attempts and set the Issuing status condition
	// to False.
	if apiutil.CertificateRequestHasInvalidRequest(req) {
		return c.failIssueCertificate(ctx, log, crt, apiutil.GetCertificateRequestCondition(req, cmapi.CertificateRequestConditionInvalidRequest))
	}

	if crReadyCond == nil {
		log.V(logf.DebugLevel).Info("CertificateRequest does not have Ready condition, waiting...")
		return nil
	}

	// If the certificate request has failed, set the last failure time to
	// now, bump the issuance attempts and set the Issuing status condition
	// to False.
	if crReadyCond.Reason == cmapi.CertificateRequestReasonFailed {
		return c.failIssueCertificate(ctx, log, crt, apiutil.GetCertificateRequestCondition(req, cmapi.CertificateRequestConditionReady))
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
	if crReadyCond.Reason == cmapi.CertificateRequestReasonIssued {
		return c.issueCertificate(ctx, nextRevision, crt, req, pk)
	}

	// Issue temporary certificate if needed. If a certificate was issued, then
	// return early - we will sync again since the target Secret has been
	// updated.
	if issued, err := c.ensureTemporaryCertificate(ctx, crt, pk); err != nil || issued {
		return err
	}

	// CertificateRequest is not in a final state so do nothing.
	log.V(logf.DebugLevel).Info("CertificateRequest not in final state, waiting...", "reason", crReadyCond.Reason)
	return nil
}

// failIssueCertificate will mark the Issuing condition of this Certificate as
// false, set the Certificate's last failure time and issuance attempts, and log
// an appropriate event. The reason and message of the Issuing condition will be that of
// the CertificateRequest condition passed.
func (c *controller) failIssueCertificate(ctx context.Context, log logr.Logger, crt *cmapi.Certificate, condition *cmapi.CertificateRequestCondition) error {
	nowTime := metav1.NewTime(c.clock.Now())
	crt.Status.LastFailureTime = &nowTime

	failedIssuanceAttempts := 1
	if crt.Status.FailedIssuanceAttempts != nil {
		failedIssuanceAttempts = *crt.Status.FailedIssuanceAttempts + 1
	}
	crt.Status.FailedIssuanceAttempts = &failedIssuanceAttempts

	log.V(logf.DebugLevel).Info("CertificateRequest in failed state so retrying issuance later")

	var reason, message string
	reason = condition.Reason
	message = fmt.Sprintf("The certificate request has failed to complete and will be retried: %s",
		condition.Message)

	crt = crt.DeepCopy()
	apiutil.SetCertificateCondition(crt, crt.Generation, cmapi.CertificateConditionIssuing, cmmeta.ConditionFalse, reason, message)

	if err := c.updateOrApplyStatus(ctx, crt, false); err != nil {
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
	secretData := internal.SecretData{
		PrivateKey:      pkData,
		Certificate:     req.Status.Certificate,
		CA:              req.Status.CA,
		CertificateName: crt.Name,
		IssuerName:      req.Spec.IssuerRef.Name,
		IssuerKind:      req.Spec.IssuerRef.Kind,
		IssuerGroup:     req.Spec.IssuerRef.Group,
	}

	if err := c.secretsUpdateData(ctx, crt, secretData); err != nil {
		return err
	}

	// Set status.revision to revision of the CertificateRequest
	crt.Status.Revision = &nextRevision

	// Remove Issuing status condition
	// TODO @joshvanl: Once we move to only server-side apply API calls, this
	// should be changed to setting the Issuing condition to False.
	apiutil.RemoveCertificateCondition(crt, cmapi.CertificateConditionIssuing)

	// Clear status.failedIssuanceAttempts (if set)
	crt.Status.FailedIssuanceAttempts = nil

	// Clear status.lastFailureTime (if set)
	crt.Status.LastFailureTime = nil

	if err := c.updateOrApplyStatus(ctx, crt, true); err != nil {
		return err
	}

	message := "The certificate has been successfully issued"
	c.recorder.Event(crt, corev1.EventTypeNormal, "Issuing", message)

	return nil

}

// updateOrApplyStatus will update the controller status. If the
// ServerSideApply feature is enabled, the managed fields will instead get
// applied using the relevant Patch API call.
// conditionRemove should be true if the Issuing condition has been removed by
// this controller. If the ServerSideApply feature is enabled and condition
// have been removed, the Issuing condition will be set to False before
// applying.
func (c *controller) updateOrApplyStatus(ctx context.Context, crt *cmapi.Certificate, conditionRemoved bool) error {
	if utilfeature.DefaultFeatureGate.Enabled(feature.ServerSideApply) {
		// TODO @joshvanl: Once we move to only server-side apply API calls,
		// `conditionRemoved` can be removed and setting the Issuing condition to
		// False can be moved to the `issueCertificate` func.
		if conditionRemoved {
			message := "The certificate has been successfully issued"
			apiutil.SetCertificateCondition(crt, crt.Generation, cmapi.CertificateConditionIssuing, cmmeta.ConditionFalse, "Issued", message)
		}

		var conditions []cmapi.CertificateCondition
		if cond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionIssuing); cond != nil {
			conditions = []cmapi.CertificateCondition{*cond}
		}

		return internalcertificates.ApplyStatus(ctx, c.client, c.fieldManager, &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{Namespace: crt.Namespace, Name: crt.Name},
			Status: cmapi.CertificateStatus{
				Revision:        crt.Status.Revision,
				LastFailureTime: crt.Status.LastFailureTime,
				Conditions:      conditions,
			},
		})
	} else {
		_, err := c.client.CertmanagerV1().Certificates(crt.Namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
		return err
	}
}

// controllerWrapper wraps the `controller` structure to make it implement
// the controllerpkg.queueingController interface
type controllerWrapper struct {
	*controller
}

func (c *controllerWrapper) Register(ctx *controllerpkg.Context) (workqueue.TypedRateLimitingInterface[types.NamespacedName], []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	log := logf.FromContext(ctx.RootContext, ControllerName)

	ctrl, queue, mustSync, err := NewController(log, ctx)
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
