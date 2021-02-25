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
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cminformers "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/trigger/policies"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/pkg/util/predicate"
)

const (
	ControllerName = "CertificateReadiness"
)

var PolicyChain = policies.Chain{
	policies.SecretDoesNotExist,
	policies.SecretHasData,
	policies.SecretPublicKeysMatch,
	policies.CurrentCertificateRequestValidForSpec,
	policies.CurrentCertificateHasExpired,
}

type controller struct {
	// the policies to use to define readiness - named here to make testing simpler
	policyChain                      policies.Chain
	certificateLister                cmlisters.CertificateLister
	certificateRequestLister         cmlisters.CertificateRequestLister
	secretLister                     corelisters.SecretLister
	client                           cmclient.Interface
	gatherer                         *policies.Gatherer
	defaultRenewBeforeExpiryDuration time.Duration
}

func NewController(
	log logr.Logger,
	client cmclient.Interface,
	factory informers.SharedInformerFactory,
	cmFactory cminformers.SharedInformerFactory,
	chain policies.Chain,
	defaultRenewBeforeExpiryDuration time.Duration,
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
		gatherer: &policies.Gatherer{
			CertificateRequestLister: certificateRequestInformer.Lister(),
			SecretLister:             secretsInformer.Lister(),
		},
		defaultRenewBeforeExpiryDuration: defaultRenewBeforeExpiryDuration,
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

	input, err := c.gatherer.DataForCertificate(ctx, crt)
	if err != nil {
		return err
	}

	condition := readyCondition(c.policyChain, input)

	crt = crt.DeepCopy()
	apiutil.SetCertificateCondition(crt, condition.Type, condition.Status, condition.Reason, condition.Message)

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
		crt.Status.NotBefore = &notBefore
		crt.Status.NotAfter = &notAfter
		// calculate how long before the certificate expiry time the certificate
		// should be renewed
		renewBefore := certificates.RenewBeforeExpiryDuration(crt.Status.NotBefore.Time, crt.Status.NotAfter.Time, crt.Spec.RenewBefore, c.defaultRenewBeforeExpiryDuration)
		renewalTime := metav1.NewTime(notAfter.Add(-1 * renewBefore))
		crt.Status.RenewalTime = &renewalTime
	default:
		// clear status fields if the secret does not have any data
		crt.Status.NotAfter = nil
		crt.Status.NotBefore = nil
		crt.Status.RenewalTime = nil
	}

	_, err = c.client.CertmanagerV1().Certificates(crt.Namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func readyCondition(chain policies.Chain, input policies.Input) cmapi.CertificateCondition {
	reason, message, reissue := chain.Evaluate(input)
	if !reissue {
		return cmapi.CertificateCondition{
			Type:    cmapi.CertificateConditionReady,
			Status:  cmmeta.ConditionTrue,
			Reason:  "Ready",
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

func (c *controllerWrapper) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	log := logf.FromContext(ctx.RootContext, ControllerName)

	ctrl, queue, mustSync := NewController(log,
		ctx.CMClient,
		ctx.KubeSharedInformerFactory,
		ctx.SharedInformerFactory,
		PolicyChain,
		cmapi.DefaultRenewBefore,
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
