/*
Copyright 2020 The Jetstack cert-manager contributors.

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
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cminformers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha2"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	certificates "github.com/jetstack/cert-manager/pkg/controller/expcertificates"
	"github.com/jetstack/cert-manager/pkg/controller/expcertificates/internal/predicate"
	"github.com/jetstack/cert-manager/pkg/controller/expcertificates/trigger/policies"
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
	// the trigger policies to run - named here to make testing simpler
	policyChain              policies.Chain
	certificateLister        cmlisters.CertificateLister
	certificateRequestLister cmlisters.CertificateRequestLister
	secretLister             corelisters.SecretLister
	client                   cmclient.Interface
	recorder                 record.EventRecorder
	clock                    clock.Clock
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
	certificateInformer := cmFactory.Certmanager().V1alpha2().Certificates()
	certificateRequestInformer := cmFactory.Certmanager().V1alpha2().CertificateRequests()
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

	reason, message, reissue := c.policyChain.Evaluate(input)
	if !reissue {
		// no reissuance required, return early
		return nil
	}

	// check if we have had a recent failure, and if so do not trigger a
	// reissue immediately
	if crt.Status.LastFailureTime != nil {
		if crt.Status.LastFailureTime.Add(time.Hour).After(c.clock.Now()) {
			durationUntilRetry := c.clock.Now().Sub(crt.Status.LastFailureTime.Time)
			log.Info("Not re-issuing certificate as an attempt has been made in the last hour", "retry_in", durationUntilRetry.String())
			return nil
		}
	}

	crt = crt.DeepCopy()
	apiutil.SetCertificateCondition(crt, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, reason, message)
	_, err = c.client.CertmanagerV1alpha2().Certificates(crt.Namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
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
