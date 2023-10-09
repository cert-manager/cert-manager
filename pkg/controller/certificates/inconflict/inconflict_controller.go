/*
Copyright 2022 The cert-manager Authors.

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

package inconflict

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	internalcertificates "github.com/cert-manager/cert-manager/internal/controller/certificates"
	"github.com/cert-manager/cert-manager/internal/controller/feature"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

var keyFunc = controllerpkg.KeyFunc

const (
	// ControllerName is the name of the certificate inconflict controller.
	ControllerName = "certificates-inconflict"

	// ReasonDuplicateSecretName is the reason set on the Certificate InConflict
	// condition when the Certificate is in conflict with another Certificate
	// in the same Namespace.
	ReasonDuplicateSecretName = "DuplicateSecretName"
)

type controller struct {
	certificateLister cmlisters.CertificateLister
	client            cmclient.Interface

	queue workqueue.RateLimitingInterface

	// fieldManager is the string which will be used as the Field Manager on
	// fields created or edited by the cert-manager Kubernetes client during
	// Apply API calls.
	fieldManager string
}

// NewController returns a new certificate duplicate-secrets controller. This
// controller is responsible for setting the InConflict condition on
// Certificates when they are using a spec.secretName which matches that of
// another Certificate in the same Namespace. This condition blocks issuance in
// other controllers to prevent CertificateRequest creation runaway.
func NewController(
	log logr.Logger,
	ctx *controllerpkg.Context,
) (*controller, workqueue.RateLimitingInterface, []cache.InformerSynced) {
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*1, time.Second*30), ControllerName)
	certificateInformer := ctx.SharedInformerFactory.Certmanager().V1().Certificates()
	certificateInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: queue})
	mustSync := []cache.InformerSynced{certificateInformer.Informer().HasSynced}

	return &controller{
		certificateLister: certificateInformer.Lister(),
		client:            ctx.CMClient,
		fieldManager:      ctx.FieldManager,
		queue:             queue,
	}, queue, mustSync
}

// ProcessItem is the reconcile loop which manages the InConflict
// condition on Certificate resources. This condition signals that the
// Certificate shares the same spec.secretName as another Certificate in the
// same Namespace.
func (c *controller) ProcessItem(ctx context.Context, key string) error {
	log := logf.FromContext(ctx).WithValues("key", key)

	ctx = logf.NewContext(ctx, log)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "invalid resource key passed to ProcessItem")
		return nil
	}

	rereconcileAll := func() error {
		crts, err := c.certificateLister.Certificates(namespace).List(labels.Everything())
		if err != nil {
			return err
		}

		for _, crt := range crts {
			// Skip Certificates that don't have the InConflict condition set.
			if apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionInConflict) == nil {
				continue
			}

			// Skip the Certificate we are currently processing.
			if crt.Name == name {
				continue
			}

			key, err := keyFunc(crt)
			if err != nil {
				log.Error(err, "error computing key for resource")
				continue
			}
			c.queue.Add(key)
		}

		return nil
	}

	crt, err := c.certificateLister.Certificates(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		// If the Certificate is not found, we can assume it has been deleted.
		// We need to re-reconcile all Certificates in the same Namespace that
		// are in conflict.

		return rereconcileAll()
	}
	if err != nil {
		log.V(logf.DebugLevel).Info("certificate not found for key", "error", err.Error())
		return nil
	}

	log = logf.WithResource(log, crt)
	ctx = logf.NewContext(ctx, log)

	// Get the Certificates in the same Namespace which have the same Secret name
	// set.
	duplicates, err := internalcertificates.DuplicateCertificateSecretNames(ctx, c.certificateLister, crt)
	if err != nil {
		return err
	}

	condition := buildDuplicateSecretNameCondition(duplicates)

	// If we don't need to update the status, return early.
	if !needsUpdate(crt, condition) {
		return nil
	}

	crt = crt.DeepCopy()
	if condition != nil {
		apiutil.SetCertificateCondition(crt, crt.Generation, condition.Type, condition.Status, condition.Reason, condition.Message)
	} else {
		// If the condition is nil, we need to remove the condition from the
		// Certificate if it exists.
		for i := range crt.Status.Conditions {
			if crt.Status.Conditions[i].Type == cmapi.CertificateConditionInConflict {
				crt.Status.Conditions = append(crt.Status.Conditions[:i], crt.Status.Conditions[i+1:]...)
				break
			}
		}
	}

	if err := c.updateOrApplyStatus(ctx, crt); err != nil {
		return err
	}

	// Reconcile all conflicting Certificates in the same Namespace.
	for _, duplicate := range duplicates {
		c.queue.Add(namespace + "/" + duplicate)
	}

	// We also need to re-reconcile all other Certificates which are in conflict.
	return rereconcileAll()
}

// needsUpdate returns true if the Certificate needs a state change because the
// Certificate doesn't have a InConflict condition when it should, or
// that condition does not reflect the state of the world.
func needsUpdate(crt *cmapi.Certificate, condition *cmapi.CertificateCondition) bool {
	existingCondition := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionInConflict)

	// Check so that the switch below doesn't panic.
	if existingCondition == nil && condition == nil {
		return false
	}

	switch {
	case (existingCondition != nil) != (condition != nil),
		existingCondition.Status != condition.Status,
		existingCondition.Reason != condition.Reason,
		existingCondition.Message != condition.Message,
		existingCondition.ObservedGeneration != crt.Generation:
		return true
	default:
		return false
	}
}

// buildDuplicateSecretNameCondition returns a nil condition if there are no
// duplicates, else, returns a InConflict condition.
func buildDuplicateSecretNameCondition(duplicates []string) *cmapi.CertificateCondition {
	if len(duplicates) == 0 {
		return nil
	}

	const msg = "Certificate shares the same Secret name as the following Certificates in this Namespace: [ %s ]. Issuance will block until this is resolved to prevent CertificateRequest creation runaway."
	return &cmapi.CertificateCondition{
		Type:    cmapi.CertificateConditionInConflict,
		Status:  cmmeta.ConditionTrue,
		Reason:  ReasonDuplicateSecretName,
		Message: fmt.Sprintf(msg, strings.Join(duplicates, ", ")),
	}
}

// updateOrApplyStatus will update the controller status. If the
// ServerSideApply feature is enabled, the managed fields will instead get
// applied using the relevant Patch API call.
func (c *controller) updateOrApplyStatus(ctx context.Context, crt *cmapi.Certificate) error {
	if utilfeature.DefaultFeatureGate.Enabled(feature.ServerSideApply) {
		var conditions []cmapi.CertificateCondition
		if cond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionInConflict); cond != nil {
			conditions = []cmapi.CertificateCondition{*cond}
		}
		return internalcertificates.ApplyStatus(ctx, c.client, c.fieldManager, &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{Namespace: crt.Namespace, Name: crt.Name},
			Status:     cmapi.CertificateStatus{Conditions: conditions},
		})
	} else {
		_, err := c.client.CertmanagerV1().Certificates(crt.Namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
		return err
	}
}

// controllerWrapper wraps the `controller` structure to make it implement the
// controllerpkg.queueingController interface.
type controllerWrapper struct {
	*controller
}

func (c *controllerWrapper) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	log := logf.FromContext(ctx.RootContext, ControllerName)

	ctrl, queue, mustSync := NewController(log, ctx)
	c.controller = ctrl

	return queue, mustSync, nil
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&controllerWrapper{}).
			Complete()
	})
}
