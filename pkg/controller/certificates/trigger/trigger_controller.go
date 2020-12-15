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

package trigger

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
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
	"github.com/jetstack/cert-manager/pkg/controller/certificates/trigger/policies"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/scheduler"
	"github.com/jetstack/cert-manager/pkg/util/predicate"
)

const (
	ControllerName = "CertificateTrigger"

	// the amount of time after the LastFailureTime of a Certificate
	// before the request should be retried.
	// In future this should be replaced with a more dynamic exponential
	// back-off algorithm.
	retryAfterLastFailure = time.Hour
)

// This controller observes the state of the certificate's currently
// issued `spec.secretName` and the rest of the `certificate.spec` fields to
// determine whether a re-issuance is required.
// It triggers re-issuance by adding the `Issuing` status condition when a new
// certificate is required.
type controller struct {
	// the trigger policies to run - named here to make testing simpler
	policyChain              policies.Chain
	certificateLister        cmlisters.CertificateLister
	certificateRequestLister cmlisters.CertificateRequestLister
	secretLister             corelisters.SecretLister
	client                   cmclient.Interface
	recorder                 record.EventRecorder
	clock                    clock.Clock
	scheduledWorkQueue       scheduler.ScheduledWorkQueue
	gatherer                 *policies.Gatherer
}

func NewController(
	log logr.Logger,
	client cmclient.Interface,
	factory informers.SharedInformerFactory,
	cmFactory cminformers.SharedInformerFactory,
	recorder record.EventRecorder,
	clock clock.Clock,
	chain policies.Chain,
) (*controller, workqueue.RateLimitingInterface, []cache.InformerSynced) {
	// create a queue used to queue up items to be processed
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*1, time.Second*30), ControllerName)

	// obtain references to all the informers used by this controller
	certificateInformer := cmFactory.Certmanager().V1().Certificates()
	certificateRequestInformer := cmFactory.Certmanager().V1().CertificateRequests()
	secretsInformer := factory.Core().V1().Secrets()

	certificateInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: queue})

	// When a CertificateRequest resource changes, enqueue the Certificate resource that owns it.
	certificateRequestInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		WorkFunc: certificates.EnqueueCertificatesForResourceUsingPredicates(log, queue, certificateInformer.Lister(), labels.Everything(), predicate.ResourceOwnerOf),
	})
	// When a Secret resource changes, enqueue any Certificate resources that name it as spec.secretName.
	secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		// Trigger reconciles on changes to the Secret named `spec.secretName`
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

	return &controller{
		policyChain:              chain,
		certificateLister:        certificateInformer.Lister(),
		certificateRequestLister: certificateRequestInformer.Lister(),
		secretLister:             secretsInformer.Lister(),
		client:                   client,
		recorder:                 recorder,
		clock:                    clock,
		scheduledWorkQueue:       scheduler.NewScheduledWorkQueue(clock, queue.Add),
		gatherer: &policies.Gatherer{
			CertificateRequestLister: certificateRequestInformer.Lister(),
			SecretLister:             secretsInformer.Lister(),
		},
	}, queue, mustSync
}

func (c *controller) ProcessItem(ctx context.Context, key string) error {
	log := logf.FromContext(ctx).WithValues("key", key)
	ctx = logf.NewContext(ctx, log)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "invalid resource key passed to ProcessItem")
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

	input, err := c.gatherer.DataForCertificate(ctx, crt)
	if err != nil {
		return err
	}

	// Back off from re-issuing immediately when the certificate has been
	// in failing mode for less than 1 hour.
	backoff, delay := shouldBackoffReissuingOnFailure(log, c.clock, input.Certificate)
	if backoff {
		log.V(logf.InfoLevel).Info("Not re-issuing certificate as an attempt has been made in the last hour", "retry_delay", delay)
		c.scheduleRecheckOfCertificateIfRequired(log, key, delay)
		return nil
	}

	if crt.Status.RenewalTime != nil {
		// ensure a resync is scheduled in the future so that we re-check
		// Certificate resources and trigger them near expiry time
		c.scheduleRecheckOfCertificateIfRequired(log, key, crt.Status.RenewalTime.Time.Sub(c.clock.Now()))
	}

	reason, message, reissue := c.policyChain.Evaluate(input)
	if !reissue {
		// no re-issuance required, return early
		return nil
	}

	crt = crt.DeepCopy()
	apiutil.SetCertificateCondition(crt, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, reason, message)
	_, err = c.client.CertmanagerV1().Certificates(crt.Namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	c.recorder.Event(crt, corev1.EventTypeNormal, "Issuing", message)

	return nil
}

// shouldBackoffReissuingOnFailure tells us if we should back off from
// reissuing the certificate and for how much time.
func shouldBackoffReissuingOnFailure(log logr.Logger, c clock.Clock, crt *cmapi.Certificate) (backoff bool, delay time.Duration) {
	if crt.Status.LastFailureTime == nil {
		return false, 0
	}

	now := c.Now()
	durationSinceFailure := now.Sub(crt.Status.LastFailureTime.Time)
	if durationSinceFailure >= retryAfterLastFailure {
		log.V(logf.ExtendedInfoLevel).WithValues("since_failure", durationSinceFailure).Info("Certificate has been in failure mode long enough, no need to back off")
		return false, 0
	}

	return true, retryAfterLastFailure - durationSinceFailure
}

// scheduleRecheckOfCertificateIfRequired will schedule the resource with the
// given key to be re-queued for processing after the given amount of time
// has elapsed.
// If the 'durationUntilRenewalTime' is less than zero, it will not be
// queued again.
func (c *controller) scheduleRecheckOfCertificateIfRequired(log logr.Logger, key string, durationUntilRenewalTime time.Duration) {
	// don't schedule a re-queue if the time is in the past.
	// if it is in the past, the resource will be triggered during the
	// current call to the ProcessItem method. If we added the item to the
	// queue with a duration of <=0, we would otherwise continually re-queue
	// in a tight loop whilst we wait for the caching listers to observe
	// the 'Triggered' status condition changing to 'True'.
	if durationUntilRenewalTime < 0 {
		return
	}

	log.V(logf.DebugLevel).Info("scheduling renewal", "duration_until_renewal", durationUntilRenewalTime.String())

	c.scheduledWorkQueue.Add(key, durationUntilRenewalTime)
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
		ctx.CMClient,
		ctx.KubeSharedInformerFactory,
		ctx.SharedInformerFactory,
		ctx.Recorder,
		ctx.Clock,
		policies.NewTriggerPolicyChain(ctx.Clock),
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
