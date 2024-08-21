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

package keymanager

import (
	"context"
	"crypto"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	internalcertificates "github.com/cert-manager/cert-manager/internal/controller/certificates"
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
	ControllerName            = "certificates-key-manager"
	reasonDecodeFailed        = "DecodeFailed"
	reasonCannotRegenerateKey = "CannotRegenerateKey"
	reasonDeleted             = "Deleted"
)

var (
	certificateGvk = cmapi.SchemeGroupVersion.WithKind("Certificate")
)

type controller struct {
	certificateLister cmlisters.CertificateLister
	secretLister      internalinformers.SecretLister
	client            cmclient.Interface
	coreClient        kubernetes.Interface
	recorder          record.EventRecorder

	// fieldManager is the string which will be used as the Field Manager on
	// fields created or edited by the cert-manager Kubernetes client during
	// Apply API calls.
	fieldManager string
}

func NewController(
	log logr.Logger, ctx *controllerpkg.Context,
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
	secretsInformer := ctx.KubeSharedInformerFactory.Secrets()

	if _, err := certificateInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: queue}); err != nil {
		return nil, nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}

	if _, err := secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		// Trigger reconciles on changes to any 'owned' secret resources
		WorkFunc: certificates.EnqueueCertificatesForResourceUsingPredicates(log, queue, certificateInformer.Lister(), labels.Everything(),
			predicate.ResourceOwnerOf,
		),
	}); err != nil {
		return nil, nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}
	if _, err := secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		// Trigger reconciles on changes to certificates named as spec.secretName
		WorkFunc: certificates.EnqueueCertificatesForResourceUsingPredicates(log, queue, certificateInformer.Lister(), labels.Everything(),
			predicate.ExtractResourceName(predicate.CertificateSecretName),
		),
	}); err != nil {
		return nil, nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		secretsInformer.Informer().HasSynced,
		certificateInformer.Informer().HasSynced,
	}

	return &controller{
		certificateLister: certificateInformer.Lister(),
		secretLister:      secretsInformer.Lister(),
		client:            ctx.CMClient,
		coreClient:        ctx.Client,
		recorder:          ctx.Recorder,
		fieldManager:      ctx.FieldManager,
	}, queue, mustSync, nil
}

// isNextPrivateKeyLabelSelector is a label selector used to match Secret
// resources with the `cert-manager.io/next-private-key: "true"` label.
var isNextPrivateKeyLabelSelector labels.Selector

func init() {
	r, err := labels.NewRequirement(cmapi.IsNextPrivateKeySecretLabelKey, selection.Equals, []string{"true"})
	if err != nil {
		panic(err)
	}
	isNextPrivateKeyLabelSelector = labels.NewSelector().Add(*r)
}

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

	// Discover all 'owned' secrets that have the `next-private-key` label
	secrets, err := certificates.ListSecretsMatchingPredicates(c.secretLister.Secrets(crt.Namespace), isNextPrivateKeyLabelSelector, predicate.ResourceOwnedBy(crt))
	if err != nil {
		return err
	}

	if !apiutil.CertificateHasCondition(crt, cmapi.CertificateCondition{
		Type:   cmapi.CertificateConditionIssuing,
		Status: cmmeta.ConditionTrue,
	}) {
		log.V(logf.DebugLevel).Info("Cleaning up Secret resources and unsetting nextPrivateKeySecretName as issuance is no longer in progress")
		if err := c.deleteSecretResources(ctx, secrets); err != nil {
			return err
		}
		return c.setNextPrivateKeySecretName(ctx, crt, nil)
	}

	// if there is no existing Secret resource, create a new one
	if len(secrets) == 0 {
		rotationPolicy := cmapi.RotationPolicyNever
		if crt.Spec.PrivateKey != nil && crt.Spec.PrivateKey.RotationPolicy != "" {
			rotationPolicy = crt.Spec.PrivateKey.RotationPolicy
		}
		switch rotationPolicy {
		case cmapi.RotationPolicyNever:
			return c.createNextPrivateKeyRotationPolicyNever(ctx, crt)
		case cmapi.RotationPolicyAlways:
			log.V(logf.DebugLevel).Info("Creating new nextPrivateKeySecretName Secret because no existing Secret found")
			return c.createAndSetNextPrivateKey(ctx, crt)
		default:
			log.V(logf.WarnLevel).Info("Certificate with unknown certificate.spec.privateKey.rotationPolicy value", "rotation_policy", rotationPolicy)
			return nil
		}
	}

	// always clean up if multiple are found
	if len(secrets) > 1 {
		// TODO: if nextPrivateKeySecretName is set, we should skip deleting that one Secret resource
		log.V(logf.DebugLevel).Info("Cleaning up Secret resources as multiple nextPrivateKeySecretName candidates found")
		return c.deleteSecretResources(ctx, secrets)
	}

	secret := secrets[0]
	log = logf.WithRelatedResource(log, secret)
	ctx = logf.NewContext(ctx, log)

	if crt.Status.NextPrivateKeySecretName == nil {
		log.V(logf.DebugLevel).Info("Adopting existing private key Secret")
		return c.setNextPrivateKeySecretName(ctx, crt, &secret.Name)
	}
	if *crt.Status.NextPrivateKeySecretName != secrets[0].Name {
		log.V(logf.DebugLevel).Info("Deleting existing private key secret as name does not match status.nextPrivateKeySecretName")
		return c.deleteSecretResources(ctx, secrets)
	}

	if secret.Data == nil || len(secret.Data[corev1.TLSPrivateKeyKey]) == 0 {
		log.V(logf.DebugLevel).Info("Deleting Secret resource as it contains no data")
		return c.deleteSecretResources(ctx, secrets)
	}
	pkData := secret.Data[corev1.TLSPrivateKeyKey]
	pk, err := pki.DecodePrivateKeyBytes(pkData)
	if err != nil {
		log.Error(err, "Deleting existing private key secret due to error decoding data")
		return c.deleteSecretResources(ctx, secrets)
	}

	violations := pki.PrivateKeyMatchesSpec(pk, crt.Spec)
	if len(violations) > 0 {
		log.V(logf.DebugLevel).Info("Regenerating private key due to change in fields", "violations", violations)
		c.recorder.Eventf(crt, corev1.EventTypeNormal, reasonDeleted, "Regenerating private key due to change in fields: %v", violations)
		return c.deleteSecretResources(ctx, secrets)
	}

	return nil
}

func (c *controller) createNextPrivateKeyRotationPolicyNever(ctx context.Context, crt *cmapi.Certificate) error {
	log := logf.FromContext(ctx)
	s, err := c.secretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)
	if apierrors.IsNotFound(err) {
		log.V(logf.DebugLevel).Info("Creating new nextPrivateKeySecretName Secret because no existing Secret found and rotation policy is Never")
		return c.createAndSetNextPrivateKey(ctx, crt)
	}
	if err != nil {
		return err
	}
	if s.Data == nil || len(s.Data[corev1.TLSPrivateKeyKey]) == 0 {
		log.V(logf.DebugLevel).Info("Creating new nextPrivateKeySecretName Secret because existing Secret contains empty data and rotation policy is Never")
		return c.createAndSetNextPrivateKey(ctx, crt)
	}
	existingPKData := s.Data[corev1.TLSPrivateKeyKey]
	pk, err := pki.DecodePrivateKeyBytes(existingPKData)
	if err != nil {
		c.recorder.Eventf(crt, corev1.EventTypeWarning, reasonDecodeFailed, "Failed to decode private key stored in Secret %q - generating new key", crt.Spec.SecretName)
		return c.createAndSetNextPrivateKey(ctx, crt)
	}
	violations := pki.PrivateKeyMatchesSpec(pk, crt.Spec)
	if len(violations) > 0 {
		c.recorder.Eventf(crt, corev1.EventTypeWarning, reasonCannotRegenerateKey, "User intervention required: existing private key in Secret %q does not match requirements on Certificate resource, mismatching fields: %v, but cert-manager cannot create new private key as the Certificate's .spec.privateKey.rotationPolicy is unset or set to Never. To allow cert-manager to create a new private key you can set .spec.privateKey.rotationPolicy to 'Always' (this will result in the private key being regenerated every time a cert is renewed) ", crt.Spec.SecretName, violations)
		return nil
	}

	nextPkSecret, err := c.createNewPrivateKeySecret(ctx, crt, pk)
	if err != nil {
		return err
	}

	c.recorder.Event(crt, corev1.EventTypeNormal, "Reused", fmt.Sprintf("Reusing private key stored in existing Secret resource %q", s.Name))

	return c.setNextPrivateKeySecretName(ctx, crt, &nextPkSecret.Name)
}

func (c *controller) createAndSetNextPrivateKey(ctx context.Context, crt *cmapi.Certificate) error {
	pk, err := pki.GeneratePrivateKeyForCertificate(crt)
	if err != nil {
		return err
	}

	s, err := c.createNewPrivateKeySecret(ctx, crt, pk)
	if err != nil {
		return err
	}

	c.recorder.Event(crt, corev1.EventTypeNormal, "Generated", fmt.Sprintf("Stored new private key in temporary Secret resource %q", s.Name))

	return c.setNextPrivateKeySecretName(ctx, crt, &s.Name)
}

// deleteSecretResources will delete the given secret resources
func (c *controller) deleteSecretResources(ctx context.Context, secrets []*corev1.Secret) error {
	log := logf.FromContext(ctx)
	for _, s := range secrets {
		if err := c.coreClient.CoreV1().Secrets(s.Namespace).Delete(ctx, s.Name, metav1.DeleteOptions{}); err != nil {
			return err
		}
		logf.WithRelatedResource(log, s).V(logf.DebugLevel).Info("Deleted 'next private key' Secret resource")
	}
	return nil
}

func (c *controller) setNextPrivateKeySecretName(ctx context.Context, crt *cmapi.Certificate, name *string) error {
	// skip updates if there has been no change
	if name == nil && crt.Status.NextPrivateKeySecretName == nil {
		return nil
	}
	if name != nil && crt.Status.NextPrivateKeySecretName != nil {
		if *name == *crt.Status.NextPrivateKeySecretName {
			return nil
		}
	}
	crt = crt.DeepCopy()
	crt.Status.NextPrivateKeySecretName = name
	return c.updateOrApplyStatus(ctx, crt)
}

// updateOrApplyStatus will update the controller status. If the
// ServerSideApply feature is enabled, the managed fields will instead get
// applied using the relevant Patch API call.
func (c *controller) updateOrApplyStatus(ctx context.Context, crt *cmapi.Certificate) error {
	if utilfeature.DefaultFeatureGate.Enabled(feature.ServerSideApply) {
		return internalcertificates.ApplyStatus(ctx, c.client, c.fieldManager, &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{Namespace: crt.Namespace, Name: crt.Name},
			Status:     cmapi.CertificateStatus{NextPrivateKeySecretName: crt.Status.NextPrivateKeySecretName},
		})
	} else {
		_, err := c.client.CertmanagerV1().Certificates(crt.Namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
		return err
	}
}

func (c *controller) createNewPrivateKeySecret(ctx context.Context, crt *cmapi.Certificate, pk crypto.Signer) (*corev1.Secret, error) {
	// if the 'nextPrivateKeySecretName' field is already set, use this as the
	// name of the Secret resource.
	name := ""
	if crt.Status.NextPrivateKeySecretName != nil {
		name = *crt.Status.NextPrivateKeySecretName
	}

	pkData, err := pki.EncodePrivateKey(pk, cmapi.PKCS8)
	if err != nil {
		return nil, err
	}

	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       crt.Namespace,
			Name:            name,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)},
			Labels: map[string]string{
				cmapi.IsNextPrivateKeySecretLabelKey:      "true",
				cmapi.PartOfCertManagerControllerLabelKey: "true",
			},
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: pkData,
		},
	}
	if s.Name == "" {
		// TODO: handle certificate resources that have especially long names
		s.GenerateName = crt.Name + "-"
	}
	s, err = c.coreClient.CoreV1().Secrets(s.Namespace).Create(ctx, s, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	return s, nil
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
