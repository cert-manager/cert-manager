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

package duplicatesecrets

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

const (
	// ControllerName is the name of the certificate duplicatesecrets controller.
	ControllerName = "certificates-duplicate-secrets"
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
// controller is responsible for setting the DuplicateSecretName condition on
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

// ProcessItem is the reconcile loop which manages the DuplicateSecretName
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

	crt, err := c.certificateLister.Certificates(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		return nil
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

	// If we don't need to update the status, return early.
	if !needsUpdate(crt, duplicates) {
		return nil
	}

	condition := buildDuplicateSecretNameCondition(duplicates)
	crt = crt.DeepCopy()
	if condition != nil {
		apiutil.SetCertificateCondition(crt, crt.Generation, condition.Type, condition.Status, condition.Reason, condition.Message)
	} else {
		// If the condition is nil, we need to remove the condition from the
		// Certificate if it exists.
		for i := range crt.Status.Conditions {
			if crt.Status.Conditions[i].Type == cmapi.CertificateConditionDuplicateSecretName {
				crt.Status.Conditions = append(crt.Status.Conditions[:i], crt.Status.Conditions[i+1:]...)
				break
			}
		}
	}

	if err := c.updateOrApplyStatus(ctx, crt); err != nil {
		return err
	}

	// We also need to re-reconcile all other Certificates which have the same
	// Secret name set so their conditions can be evaluated.
	for _, duplicate := range duplicates {
		c.queue.Add(crt.Namespace + "/" + duplicate)
	}

	return nil
}

// needsUpdate returns true if the Certificate needs a state change because the
// Certificate doesn't have a DuplicateSecretName condition when it should, or
// that condition does not reflect the state of the world.
func needsUpdate(crt *cmapi.Certificate, duplicates []string) bool {
	existingCondition := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionDuplicateSecretName)
	if len(duplicates) == 0 && existingCondition == nil {
		return false
	}

	condition := buildDuplicateSecretNameCondition(duplicates)

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
// duplicates, else, returns a DuplicateSecretName condition.
func buildDuplicateSecretNameCondition(duplicates []string) *cmapi.CertificateCondition {
	if len(duplicates) == 0 {
		return nil
	}

	const msg = "Certificate shares the same Secret name as the following Certificates in this Namespace: [ %s ]. Issuance will block until this is resolved to prevent CertificateRequest creation runaway."
	return &cmapi.CertificateCondition{
		Type:    cmapi.CertificateConditionDuplicateSecretName,
		Status:  cmmeta.ConditionTrue,
		Reason:  strings.Join(duplicates, ","),
		Message: fmt.Sprintf(msg, strings.Join(duplicates, ", ")),
	}
}

// updateOrApplyStatus will update the controller status. If the
// ServerSideApply feature is enabled, the managed fields will instead get
// applied using the relevant Patch API call.
func (c *controller) updateOrApplyStatus(ctx context.Context, crt *cmapi.Certificate) error {
	if utilfeature.DefaultFeatureGate.Enabled(feature.ServerSideApply) {
		var conditions []cmapi.CertificateCondition
		if cond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionDuplicateSecretName); cond != nil {
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
