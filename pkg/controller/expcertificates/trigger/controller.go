package trigger

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha2"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	certificates "github.com/jetstack/cert-manager/pkg/controller/expcertificates"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

const (
	ControllerName = "CertificateTrigger"
)

var (
	certificateGvk = cmapi.SchemeGroupVersion.WithKind("Certificate")
)

// This controller observes the state of the certificate's currently
// issued `spec.secretName` and the rest of the `certificate.spec` fields to
// determine whether a re-issuance is required.
// It triggers re-issuance by adding the `Issuing` status condition when a new
// certificate is required.
type controller struct {
	certificateLister        cmlisters.CertificateLister
	certificateRequestLister cmlisters.CertificateRequestLister
	secretLister             corelisters.SecretLister
	client                   cmclient.Interface
	recorder                 record.EventRecorder
	clock                    clock.Clock
}

func (c *controller) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, []controllerpkg.RunFunc, error) {
	// construct a new named logger to be reused throughout the controller
	log := logf.FromContext(ctx.RootContext, ControllerName)

	// create a queue used to queue up items to be processed
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*1, time.Second*30), ControllerName)

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

	c.certificateLister = certificateInformer.Lister()
	c.certificateRequestLister = certificateRequestInformer.Lister()
	c.secretLister = secretsInformer.Lister()
	c.recorder = ctx.Recorder
	c.client = ctx.CMClient
	c.clock = ctx.Clock

	certificateInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: queue})
	certificateRequestInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		WorkFunc: controllerpkg.HandleOwnedResourceNamespacedFunc(log, queue, certificateGvk, certificates.CertificateGetFunc(c.certificateLister)),
	})
	secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		// Trigger reconciles on changes to the Secret named `spec.secretName`
		WorkFunc: certificates.EnqueueCertificatesForSecretNameFunc(log, c.certificateLister, labels.Everything(), queue),
	})

	return queue, mustSync, nil, nil
}

func (c *controller) ProcessItem(ctx context.Context, key string) error {
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
	if apiutil.CertificateHasCondition(crt, cmapi.CertificateCondition{
		Type:   cmapi.CertificateConditionIssuing,
		Status: cmmeta.ConditionTrue,
	}) {
		// Do nothing if an issuance is already in progress.
		return nil
	}

	input, err := c.buildPolicyInputForCertificate(crt)
	if err != nil {
		return err
	}

	reason, message, reissue := evaluatePolicyChain(*input, defaultPolicyChain...)
	if !reissue {
		// no reissuance required, return early
		return nil
	}

	// check if we have had a recent failure, and if so do not trigger a
	// reissue immediately
	if crt.Status.LastFailureTime != nil {
		if crt.Status.LastFailureTime.Add(time.Hour).Before(c.clock.Now()) {
			durationUntilRetry := c.clock.Now().Sub(crt.Status.LastFailureTime.Time)
			log.Info("Not re-issuing certificate as an attempt has been made in the last hour", "retry_in", durationUntilRetry.String())
			return nil
		}
	}

	crt = crt.DeepCopy()
	apiutil.SetCertificateCondition(crt, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, reason, message)
	_, err = c.client.CertmanagerV1alpha2().Certificates(crt.Namespace).UpdateStatus(crt)
	if err != nil {
		return err
	}
	c.recorder.Event(crt, corev1.EventTypeNormal, "Issuing", message)

	return nil
}

func (c *controller) buildPolicyInputForCertificate(crt *cmapi.Certificate) (*policyInput, error) {
	// Attempt to fetch the secret being managed but tolerate NotFound errors.
	secret, err := c.secretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}

	// Attempt to fetch the CertificateRequest resource for the current 'status.revision'.
	var req *cmapi.CertificateRequest
	if crt.Status.Revision != nil {
		reqs, err := certificates.ListCertificateRequestsMatchingPredicate(c.certificateRequestLister.CertificateRequests(crt.Namespace),
			labels.Everything(),
			certificates.WithCertificateRevisionPredicateFunc(*crt.Status.Revision),
		)
		if err != nil {
			return nil, err
		}
		if len(reqs) > 1 {
			return nil, fmt.Errorf("multiple CertificateRequest resources for the current revision, not triggering new issuance until requests have been cleaned up")
		}
		if len(reqs) == 1 {
			req = reqs[0]
		}
	}

	return &policyInput{
		certificate:            crt,
		currentRevisionRequest: req,
		secret:                 secret,
	}, nil
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&controller{}).
			Complete()
	})
}
