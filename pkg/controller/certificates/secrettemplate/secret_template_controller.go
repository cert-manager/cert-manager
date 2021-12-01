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

package secrettemplate

import (
	"bytes"
	"context"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/structured-merge-diff/v4/fieldpath"

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
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/predicate"
)

const (
	// ControllerName is the name of the certificate SecretTemplate controller.
	ControllerName = "certificates-secret-template"
)

type controller struct {
	certificateLister cmlisters.CertificateLister
	secretLister      corelisters.SecretLister
	client            cmclient.Interface

	// fieldManager is the string which will be used as the field Manager on
	// fields created or edited by the cert-manager Kubernetes client.
	fieldManager string

	// secretsUpdateData is used by the SecretTemplate controller for
	// re-reconciling Secrets where the SecretTemplate is not up to date with a
	// Certificate's secret.
	secretsUpdateData func(context.Context, *cmapi.Certificate, secretsmanager.SecretData) error
}

// NewController returns a new certificate SecretTemplate controller.
func NewController(
	log logr.Logger,
	kubeClient kubernetes.Interface,
	restConfig *rest.Config,
	client cmclient.Interface,
	factory informers.SharedInformerFactory,
	cmFactory cminformers.SharedInformerFactory,
	certificateControllerOptions controllerpkg.CertificateOptions,
) (*controller, workqueue.RateLimitingInterface, []cache.InformerSynced) {
	// create a queue used to queue up items to be processed
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*1, time.Second*30), ControllerName)

	// obtain references to all the informers used by this controller
	certificateInformer := cmFactory.Certmanager().V1().Certificates()
	secretsInformer := factory.Core().V1().Secrets()

	certificateInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: queue})

	// When a Secret resource changes, enqueue any Certificate resources that name it as spec.secretName.
	secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		// Trigger reconciles on changes to the Secret named `spec.secretName`
		WorkFunc: certificates.EnqueueCertificatesForResourceUsingPredicates(log, queue, certificateInformer.Lister(), labels.Everything(),
			predicate.ExtractResourceName(predicate.CertificateSecretName)),
	})

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		secretsInformer.Informer().HasSynced,
		certificateInformer.Informer().HasSynced,
	}

	secretsManager := secretsmanager.New(
		kubeClient,
		secretsInformer.Lister(),
		restConfig,
		certificateControllerOptions.EnableOwnerRef,
	)

	return &controller{
		certificateLister: certificateInformer.Lister(),
		secretLister:      secretsInformer.Lister(),
		fieldManager:      util.PrefixFromUserAgent(restConfig.UserAgent),
		secretsUpdateData: secretsManager.UpdateData,
		client:            client,
	}, queue, mustSync
}

// ProcessItem is a worker function that will be called when a new key
// corresponding to a Certificate to be re-synced is pulled from the workqueue.
// ProcessItem will re-reocncile a Certificate's Secret if it is both
// 1. In a Ready state;
// 2. The Secret Annotations/Labels are out-of-sync with the Certificate's
//    SecretTemplate.
func (c *controller) ProcessItem(ctx context.Context, key string) error {
	log := logf.FromContext(ctx).WithValues("key", key)
	dbg := log.V(logf.DebugLevel)

	log.Info("syncing secret template")

	ctx = logf.NewContext(ctx, log)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "invalid resource key passed to ProcessItem")
		return nil
	}

	crt, err := c.certificateLister.Certificates(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		dbg.Info("certificate not found for key", "error", err.Error())
		return nil
	}
	if err != nil {
		return err
	}

	// We don't need to DeepCopy the Certificate since we never make any
	// modifications to the object.

	log = logf.WithResource(log, crt)

	// If the Certificate if not in a Ready condition, exit early. It is only
	// safe to reconcile Certificates which are Ready, so to not disturb other
	// Certificates controllers, namely the issuing controller.
	if !apiutil.CertificateHasCondition(crt, cmapi.CertificateCondition{
		Type:   cmapi.CertificateConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		return nil
	}

	// Retrieve the Secret which is associated with this Certificate.
	secret, err := c.secretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)

	// Secret doesn't exist so we can't do anything. The Certificate will be
	// marked for a re-issuance and the resulting Secret will be evaluated again.
	if apierrors.IsNotFound(err) {
		dbg.Info("secret not found", "error", err.Error())
		return nil
	}

	// This error is transient, return error to be retired on the rate limiting
	// queue.
	if err != nil {
		return err
	}

	secret = secret.DeepCopy()

	log = log.WithValues("secret", secret.Name)

	// Check whether the Certificate's SecretTemplate matches that on the Secret.
	secretTemplateMatchManagedFields, err := c.secretTemplateMatchesManagedFields(crt, secret)

	if err != nil {
		// An error here indicates that the managed fields are malformed, or the
		// decoder doesn't understand the managed fields on the Secret. There is
		// nothing more the controller can do here, so we exit nil so this
		// controller doesn't end in an infinite loop.
		log.Error(err, "failed to decode the Secret's managed field")
		return nil
	}

	// - secretTemplateMatchesSecret: If a key or value changed on the
	// Annotations or Labels in the SecretTemplate, the SecretTemplate will not
	// match the Annotations or Labels on the Secret.
	// - secretTemplateMatchManagedFields: If a key was removed on the
	// SecretTemplate, then the managed fields on the Secret won't match.
	// In either case, the Secret needs to be re-reconciled with the Secrets
	// Manager.
	if !secretTemplateMatchesSecret(crt, secret) || !secretTemplateMatchManagedFields {
		log.Info("miss-match between SecretTemplate and Secret, updating Secret annotations/labels")
		return c.secretsUpdateData(ctx, crt, secretsmanager.SecretData{
			PrivateKey:  secret.Data[corev1.TLSPrivateKeyKey],
			Certificate: secret.Data[corev1.TLSCertKey],
			CA:          secret.Data[cmmeta.TLSCAKey],
		})
	}

	// SecretTemplate matches Secret, nothing to do.

	return nil
}

// secretTemplateMatchesSecret will inspect the given Secret's Annotations and
// Labels, and compare these maps against those that appear on the given
// Certificate's SecretTemplate.
// Returns true if all the Certificate's SecretTemplate Annotations and Labels
// appear on the Secret, or put another way, the Secret Annotations/Labels are
// a subset of that in the Certificate's SecretTemplate. Returns false
// otherwise.
func secretTemplateMatchesSecret(crt *cmapi.Certificate, secret *corev1.Secret) bool {
	if crt.Spec.SecretTemplate == nil {
		return true
	}

	for kSpec, vSpec := range crt.Spec.SecretTemplate.Annotations {
		if v, ok := secret.Annotations[kSpec]; !ok || v != vSpec {
			return false
		}
	}

	for kSpec, vSpec := range crt.Spec.SecretTemplate.Labels {
		if v, ok := secret.Labels[kSpec]; !ok || v != vSpec {
			return false
		}
	}

	return true
}

// secretTemplateMatchesManagedFields will inspect the given Secret's managed
// fields for its Annotations and Labels, and compare this against the
// SecretTemplate on the given Certificate. Returns true if Annotations and
// Labels match on both the Certificate's SecretTemplate and the Secret's
// managed fields, false otherwise.
// An error is returned if the managed fields were not able to be decoded.
func (c *controller) secretTemplateMatchesManagedFields(crt *cmapi.Certificate, secret *corev1.Secret) (bool, error) {
	var managedLabels, managedAnnotations []string
	for _, managedField := range secret.ManagedFields {
		// If the managed field isn't owned by the cert-manager controller, ignore.
		if managedField.Manager != c.fieldManager || managedField.FieldsV1 == nil {
			continue
		}

		// Decode the managed field.
		var fieldset fieldpath.Set
		if err := fieldset.FromJSON(bytes.NewReader(managedField.FieldsV1.Raw)); err != nil {
			return false, err
		}

		// Extract the labels and annotations of the managed fields.
		metadata := fieldset.Children.Descend(fieldpath.PathElement{
			FieldName: pointer.String("metadata"),
		})
		labels := metadata.Children.Descend(fieldpath.PathElement{
			FieldName: pointer.String("labels"),
		})
		annotations := metadata.Children.Descend(fieldpath.PathElement{
			FieldName: pointer.String("annotations"),
		})

		// Gather the annotations and labels on the managed fields. Remove the '.'
		// prefix which appears on managed field keys.
		labels.Iterate(func(path fieldpath.Path) {
			managedLabels = append(managedLabels, strings.TrimPrefix(path.String(), "."))
		})
		annotations.Iterate(func(path fieldpath.Path) {
			managedAnnotations = append(managedAnnotations, strings.TrimPrefix(path.String(), "."))
		})
	}

	managedLabels = util.DeDuplicate(managedLabels)
	managedAnnotations = util.DeDuplicate(managedAnnotations)

	// Check early for Secret Template being nil, and whether managed
	// labels/annotations are not.
	if crt.Spec.SecretTemplate == nil {
		if len(managedLabels) > 0 || len(managedAnnotations) > 0 {
			return false, nil
		}
		// SecretTemplate is nil. Managed annotations and labels are also empty.
		// Return true.
		return true, nil
	}

	// SecretTemplate is not nil. Do length checks.
	if len(crt.Spec.SecretTemplate.Labels) != len(managedLabels) ||
		len(crt.Spec.SecretTemplate.Annotations) != len(managedAnnotations) {
		return false, nil
	}

	// Check equal unsorted for SecretTemplate keys, and the managed fields
	// equivalents.
	for _, smap := range []struct {
		specMap      map[string]string
		managedSlice []string
	}{
		{specMap: crt.Spec.SecretTemplate.Labels, managedSlice: managedLabels},
		{specMap: crt.Spec.SecretTemplate.Annotations, managedSlice: managedAnnotations},
	} {
		var specSlice []string
		for kSpec := range smap.specMap {
			specSlice = append(specSlice, kSpec)
		}

		if !util.EqualUnsorted(specSlice, smap.managedSlice) {
			return false, nil
		}
	}

	return true, nil
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
		ctx.RESTConfig,
		ctx.CMClient,
		ctx.KubeSharedInformerFactory,
		ctx.SharedInformerFactory,
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
