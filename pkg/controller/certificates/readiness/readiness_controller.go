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

package readiness

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

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
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/pkg/util/predicate"
)

const (
	// ControllerName is the name of the certificate readiness controller.
	ControllerName = "certificates-readiness"
	// ReadyReason is the 'Ready' reason of a Certificate.
	ReadyReason = "Ready"
)

type controller struct {
	// the policies to use to define readiness - named here to make testing simpler
	policyChain              policies.Chain
	certificateLister        cmlisters.CertificateLister
	certificateRequestLister cmlisters.CertificateRequestLister
	secretLister             internalinformers.SecretLister
	client                   cmclient.Interface
	gatherer                 *policies.Gatherer
	// policyEvaluator builds Ready condition of a Certificate based on policy evaluation
	policyEvaluator policyEvaluatorFunc
	// renewalTimeCalculator calculates renewal time of a certificate
	renewalTimeCalculator pki.RenewalTimeFunc

	// fieldManager is the string which will be used as the Field Manager on
	// fields created or edited by the cert-manager Kubernetes client during
	// Apply API calls.
	fieldManager string
}

// readyConditionFunc is custom function type that builds certificate's Ready condition
type policyEvaluatorFunc func(policies.Chain, policies.Input) cmapi.CertificateCondition

// NewController returns a new certificate readiness controller.
func NewController(
	log logr.Logger,
	ctx *controllerpkg.Context,
	chain policies.Chain,
	renewalTimeCalculator pki.RenewalTimeFunc,
	policyEvaluator policyEvaluatorFunc,
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

	// When a CertificateRequest resource changes, enqueue the Certificate resource that owns it.
	if _, err := certificateRequestInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		WorkFunc: certificates.EnqueueCertificatesForResourceUsingPredicates(log, queue, certificateInformer.Lister(), labels.Everything(), predicate.ResourceOwnerOf),
	}); err != nil {
		return nil, nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}
	// When a Secret resource changes, enqueue any Certificate resources that name it as spec.secretName.
	if _, err := secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		// Trigger reconciles on changes to the Secret named `spec.secretName`
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

	return &controller{
		policyChain:              chain,
		certificateLister:        certificateInformer.Lister(),
		certificateRequestLister: certificateRequestInformer.Lister(),
		secretLister:             secretsInformer.Lister(),
		client:                   ctx.CMClient,
		gatherer: &policies.Gatherer{
			CertificateRequestLister: certificateRequestInformer.Lister(),
			SecretLister:             secretsInformer.Lister(),
		},
		policyEvaluator:       policyEvaluator,
		renewalTimeCalculator: renewalTimeCalculator,
		fieldManager:          ctx.FieldManager,
	}, queue, mustSync, nil
}

// ProcessItem is a worker function that will be called when a new key
// corresponding to a Certificate to be re-synced is pulled from the workqueue.
// ProcessItem will update the Ready condition of a Certificate.
func (c *controller) ProcessItem(ctx context.Context, key types.NamespacedName) error {
	log := logf.FromContext(ctx).WithValues("key", key)

	ctx = logf.NewContext(ctx, log)
	namespace, name := key.Namespace, key.Name

	crt, err := c.certificateLister.Certificates(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		log.V(logf.DebugLevel).Info("certificate not found for key", "error", err.Error())
		return nil
	}
	if err != nil {
		return err
	}

	input, err := c.gatherer.DataForCertificate(ctx, crt)
	if err != nil {
		return err
	}

	condition := c.policyEvaluator(c.policyChain, input)
	oldCrt := crt
	crt = crt.DeepCopy()
	apiutil.SetCertificateCondition(crt, crt.Generation, condition.Type, condition.Status, condition.Reason, condition.Message)

	switch {
	case input.Secret != nil && input.Secret.Data != nil:
		x509cert, err := pki.DecodeX509CertificateBytes(input.Secret.Data[corev1.TLSCertKey])
		if err != nil {
			// clear status fields if we cannot decode the certificate bytes
			crt.Status.NotAfter = nil
			crt.Status.NotBefore = nil
			crt.Status.RenewalTime = nil
			break
		}

		notBefore := metav1.NewTime(x509cert.NotBefore)
		notAfter := metav1.NewTime(x509cert.NotAfter)
		renewalTime := c.renewalTimeCalculator(x509cert.NotBefore, x509cert.NotAfter, crt.Spec.RenewBefore, crt.Spec.RenewBeforePercentage)

		// update Certificate's Status
		crt.Status.NotBefore = &notBefore
		crt.Status.NotAfter = &notAfter
		crt.Status.RenewalTime = renewalTime

	default:
		// clear status fields if the secret does not have any data
		crt.Status.NotAfter = nil
		crt.Status.NotBefore = nil
		crt.Status.RenewalTime = nil
	}
	if !apiequality.Semantic.DeepEqual(oldCrt.Status, crt.Status) {
		log.V(logf.DebugLevel).Info("updating status fields", "notAfter",
			crt.Status.NotAfter, "notBefore", crt.Status.NotBefore, "renewalTime",
			crt.Status.RenewalTime)
		return c.updateOrApplyStatus(ctx, crt)
	}
	return nil
}

// updateOrApplyStatus will update the controller status. If the
// ServerSideApply feature is enabled, the managed fields will instead get
// applied using the relevant Patch API call.
func (c *controller) updateOrApplyStatus(ctx context.Context, crt *cmapi.Certificate) error {
	if utilfeature.DefaultFeatureGate.Enabled(feature.ServerSideApply) {
		var conditions []cmapi.CertificateCondition
		if cond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionReady); cond != nil {
			conditions = []cmapi.CertificateCondition{*cond}
		}
		return internalcertificates.ApplyStatus(ctx, c.client, c.fieldManager, &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{Namespace: crt.Namespace, Name: crt.Name},
			Status: cmapi.CertificateStatus{
				NotAfter:    crt.Status.NotAfter,
				NotBefore:   crt.Status.NotBefore,
				RenewalTime: crt.Status.RenewalTime,
				Conditions:  conditions,
			},
		})
	} else {
		_, err := c.client.CertmanagerV1().Certificates(crt.Namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
		return err
	}
}

// BuildReadyConditionFromChain builds Certificate's Ready condition using the result of policy chain evaluation
func BuildReadyConditionFromChain(chain policies.Chain, input policies.Input) cmapi.CertificateCondition {
	reason, message, violationsFound := chain.Evaluate(input)
	if !violationsFound {
		return cmapi.CertificateCondition{
			Type:    cmapi.CertificateConditionReady,
			Status:  cmmeta.ConditionTrue,
			Reason:  ReadyReason,
			Message: "Certificate is up to date and has not expired",
		}
	}
	return cmapi.CertificateCondition{
		Type:    cmapi.CertificateConditionReady,
		Status:  cmmeta.ConditionFalse,
		Reason:  reason,
		Message: message,
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

	ctrl, queue, mustSync, err := NewController(log,
		ctx,
		policies.NewReadinessPolicyChain(ctx.Clock),
		pki.RenewalTime,
		BuildReadyConditionFromChain,
	)
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
