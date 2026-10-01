/*
Copyright 2023 The cert-manager Authors.

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

package informers

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	kubeinformers "k8s.io/client-go/informers"
	certificatesv1 "k8s.io/client-go/informers/certificates/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	internalinterfaces "k8s.io/client-go/informers/internalinterfaces"
	networkingv1informers "k8s.io/client-go/informers/networking/v1"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/client-go/metadata/metadatalister"
	"k8s.io/client-go/tools/cache"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// This file contains all the functionality for implementing core informers with a filter for Secrets
// https://github.com/cert-manager/cert-manager/blob/master/design/20221205-memory-management.md
var (
	isCertManageSecretLabelSelector     labels.Selector
	isNotCertManagerSecretLabelSelector labels.Selector
)

func init() {
	r, err := labels.NewRequirement(cmapi.PartOfCertManagerControllerLabelKey, selection.Equals, []string{"true"})
	if err != nil {
		panic(fmt.Errorf("internal error: failed to build label selector to filter cert-manager secrets: %w", err))
	}
	isCertManageSecretLabelSelector = labels.NewSelector().Add(*r)

	r, err = labels.NewRequirement(cmapi.PartOfCertManagerControllerLabelKey, selection.DoesNotExist, nil)
	if err != nil {
		panic(fmt.Errorf("internal error: failed to build label selector to filter non-cert-manager secrets: %w", err))
	}
	isNotCertManagerSecretLabelSelector = labels.NewSelector().Add(*r)
}

type filteredSecretsFactory struct {
	typedInformerFactory    kubeinformers.SharedInformerFactory
	metadataInformerFactory metadatainformer.SharedInformerFactory
	client                  kubernetes.Interface
	namespace               string
	ctx                     context.Context
}

func NewFilteredSecretsKubeInformerFactory(ctx context.Context, typedClient kubernetes.Interface, metadataClient metadata.Interface, resync time.Duration, namespace string) KubeInformerFactory {
	return &filteredSecretsFactory{
		typedInformerFactory: kubeinformers.NewSharedInformerFactoryWithOptions(typedClient, resync, kubeinformers.WithNamespace(namespace)),
		metadataInformerFactory: metadatainformer.NewFilteredSharedInformerFactory(metadataClient, resync, namespace, func(listOptions *metav1.ListOptions) {
			listOptions.LabelSelector = isNotCertManagerSecretLabelSelector.String()

		}),
		// namespace is set to a non-empty value if cert-manager
		// controller is scoped to a single namespace via --namespace
		// flag
		namespace: namespace,
		client:    typedClient,
		// Go recommends to not store context in
		// structs, but here we have no other way as we need to use root context inside
		// Get whose signature is defined upstream and does not accept context
		ctx: ctx,
	}
}

func (bf *filteredSecretsFactory) Start(stopCh <-chan struct{}) {
	bf.typedInformerFactory.Start(stopCh)
	bf.metadataInformerFactory.Start(stopCh)
}

func (bf *filteredSecretsFactory) WaitForCacheSync(stopCh <-chan struct{}) map[string]bool {
	caches := make(map[string]bool)
	typedCaches := bf.typedInformerFactory.WaitForCacheSync(stopCh)
	partialMetaCaches := bf.metadataInformerFactory.WaitForCacheSync(stopCh)
	// We have to cast the keys into string type. It is not possible to
	// create a generic type here as neither of the types returned by
	// WaitForCacheSync are valid map key arguments in generics - they aren't
	// comparable types.
	for key, val := range typedCaches {
		caches[key.String()] = val
	}
	for key, val := range partialMetaCaches {
		caches[key.String()] = val
	}
	return caches
}

func (bf *filteredSecretsFactory) Shutdown() {
	bf.typedInformerFactory.Shutdown()
	bf.metadataInformerFactory.Shutdown()
}

func (bf *filteredSecretsFactory) Ingresses() networkingv1informers.IngressInformer {
	return bf.typedInformerFactory.Networking().V1().Ingresses()
}

func (bf *filteredSecretsFactory) CertificateSigningRequests() certificatesv1.CertificateSigningRequestInformer {
	return bf.typedInformerFactory.Certificates().V1().CertificateSigningRequests()
}

func (bf *filteredSecretsFactory) Secrets() SecretInformer {
	f := func(client kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return corev1informers.NewFilteredSecretInformer(client, bf.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, func(listOptions *metav1.ListOptions) {
			listOptions.LabelSelector = isCertManageSecretLabelSelector.String()
		})
	}
	return &filteredSecretInformer{
		typedInformerFactory:    bf.typedInformerFactory,
		metadataInformerFactory: bf.metadataInformerFactory,
		namespace:               bf.namespace,
		typedClient:             bf.client.CoreV1(),
		newTyped:                f,
		ctx:                     bf.ctx,
	}
}

// filteredSecretInformer is an implementation of SecretInformer that uses two
// caches (typed and metadata) to list and watch Secrets
type filteredSecretInformer struct {
	typedInformerFactory    kubeinformers.SharedInformerFactory
	metadataInformerFactory metadatainformer.SharedInformerFactory
	typedClient             typedcorev1.SecretsGetter
	newTyped                internalinterfaces.NewInformerFunc

	namespace string
	// Go recommends to not store context in
	// structs, but here we have no other way as we need to use root context inside
	// Get whose signature is defined upstream and does not accept context
	ctx context.Context
}

func (f *filteredSecretInformer) Informer() Informer {
	typedInformer := f.typedInformerFactory.InformerFor(&corev1.Secret{}, f.newTyped)

	metadataInformer := f.metadataInformerFactory.ForResource(secretsGVR).Informer()
	if err := metadataInformer.SetTransform(partialMetadataRemoveAll); err != nil {
		panic(fmt.Sprintf("internal error: error setting transformer on the metadata informer: %v", err))
	}
	return &informer{
		typedInformer:    typedInformer,
		metadataInformer: metadataInformer,
	}
}

func (f *filteredSecretInformer) Lister() SecretLister {
	typedLister := corev1listers.NewSecretLister(f.typedInformerFactory.InformerFor(&corev1.Secret{}, f.newTyped).GetIndexer())
	metadataLister := metadatalister.New(f.metadataInformerFactory.ForResource(secretsGVR).Informer().GetIndexer(), secretsGVR)
	return &secretLister{
		typedClient:           f.typedClient,
		namespace:             f.namespace,
		typedLister:           typedLister,
		partialMetadataLister: metadataLister,
		ctx:                   f.ctx,
	}
}

// informer is an implementation of Informer interface
type informer struct {
	typedInformer    cache.SharedIndexInformer
	metadataInformer cache.SharedIndexInformer
}

func (i *informer) HasSynced() bool {
	return i.typedInformer.HasSynced() && i.metadataInformer.HasSynced()
}

func (i *informer) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	_, err := i.metadataInformer.AddEventHandler(handler)
	if err != nil {
		return nil, err
	}
	_, err = i.typedInformer.AddEventHandler(handler)
	return nil, err
}

// secretLister is an implementation of SecretLister with a namespaced lister
// that knows how to do conditional GET/LIST of Secrets using a combination of
// typed and metadata cache and kube apiserver
type secretLister struct {
	namespace             string
	partialMetadataLister metadatalister.Lister
	typedLister           corev1listers.SecretLister
	typedClient           typedcorev1.SecretsGetter
	// Go recommends to not store context in
	// structs, but here we have no other way as we need to use root context inside
	// Get whose signature is defined upstream and does not accept context
	ctx context.Context
}

func (sl *secretLister) Secrets(namespace string) corev1listers.SecretNamespaceLister {
	return &secretNamespaceLister{
		namespace:             namespace,
		partialMetadataLister: sl.partialMetadataLister,
		typedLister:           sl.typedLister,
		typedClient:           sl.typedClient,
		ctx:                   sl.ctx,
	}
}

var _ corev1listers.SecretNamespaceLister = &secretNamespaceLister{}

// secretNamespaceLister is an implementation of
// corelisters.SecretNamespaceLister
// https://github.com/kubernetes/client-go/blob/0382bf0f53b2294d4ac448203718f0ba774a477d/listers/core/v1/secret.go#L62-L72.
// It knows how to get and list Secrets using typed and partial metadata caches
// and kube apiserver. It looks for Secrets in both caches, if the Secret is
// found in metadata cache, it will retrieve it from kube apiserver.
type secretNamespaceLister struct {
	namespace             string
	partialMetadataLister metadatalister.Lister
	typedLister           corev1listers.SecretLister
	typedClient           typedcorev1.SecretsGetter
	// Go recommends to not store context in
	// structs, but here we have no other way as we need to use root context inside
	// Get whose signature is defined upstream and does not accept context
	ctx context.Context
}

func (snl *secretNamespaceLister) Get(name string) (*corev1.Secret, error) {
	log := logf.FromContext(snl.ctx)
	log = log.WithValues("secret", name, "namespace", snl.namespace)

	var secretFoundInTypedCache, secretFoundInMetadataCache bool
	secret, typedCacheErr := snl.typedLister.Secrets(snl.namespace).Get(name)
	if typedCacheErr == nil {
		secretFoundInTypedCache = true
	}

	if typedCacheErr != nil && !apierrors.IsNotFound(typedCacheErr) {
		log.Error(typedCacheErr, "error getting secret from typed cache")
		return nil, fmt.Errorf("error retrieving secret from the typed cache: %w", typedCacheErr)
	}
	_, partialMetadataGetErr := snl.partialMetadataLister.Namespace(snl.namespace).Get(name)
	if partialMetadataGetErr == nil {
		secretFoundInMetadataCache = true
	}

	if partialMetadataGetErr != nil && !apierrors.IsNotFound(partialMetadataGetErr) {
		log.Error(partialMetadataGetErr, "error getting secret from metadata cache")
		return nil, fmt.Errorf("error retrieving object from partial object metadata cache: %w", partialMetadataGetErr)
	}

	if secretFoundInMetadataCache {
		// if secret is found in both caches log an error and return the version from kube apiserver
		if secretFoundInTypedCache {
			key := types.NamespacedName{Namespace: snl.namespace, Name: name}
			log.Info(fmt.Sprintf("warning: possible internal error: stale cache: secret found both in typed cache and in partial cache: %s", pleaseOpenIssue), "secret", key)
		}
		return snl.typedClient.Secrets(snl.namespace).Get(snl.ctx, name, metav1.GetOptions{})
	}

	if secretFoundInTypedCache {
		return secret, nil
	}

	// If we get here it is because secret was found neither in typed cache
	// nor partial metadata cache
	return nil, apierrors.NewNotFound(schema.GroupResource{Group: corev1.GroupName, Resource: corev1.ResourceSecrets.String()}, name)
}

func (snl *secretNamespaceLister) List(selector labels.Selector) ([]*corev1.Secret, error) {
	log := logf.FromContext(snl.ctx)
	log = log.WithValues("secrets namespace", snl.namespace, "secrets selector", selector.String())
	matchingSecretsMap := make(map[types.NamespacedName]*corev1.Secret)
	typedSecrets, err := snl.typedLister.List(selector)
	if err != nil {
		log.Error(err, "error listing Secrets from typed cache")
		return nil, fmt.Errorf("error listing Secrets from typed cache: %w", err)
	}
	for _, secret := range typedSecrets {
		key := types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}
		matchingSecretsMap[key] = secret
	}
	metadataSecrets, err := snl.partialMetadataLister.List(selector)
	if err != nil {
		log.Error(err, "error listing Secrets from metadata only cache")
		return nil, fmt.Errorf("error listing Secrets from metadata only cache: %w", err)
	}

	if len(metadataSecrets) > 0 {
		// Only selectors that match the empty label set reach this branch: the
		// metadata cache's transform strips labels, so a selector matching a
		// positive requirement never returns a non-cert-manager Secret. On
		// master nothing here was reachable at all (the keymanager lists with
		// isNextPrivateKeyLabelSelector), and the warning below is the only
		// thing that would surface a future caller, so it stays.
		log.V(logf.WarnLevel).Info("unexpected behaviour: Secrets LISTed from the metadata cache. Please open an issue",
			"secrets namespace", snl.namespace, "secrets selector", selector.String(),
			"metadata cache matches", len(metadataSecrets))

		// Secrets LISTed from the metadata cache are not usable as
		// corev1.Secrets, so each of them used to be fetched live with
		// one GET per Secret
		// (https://github.com/cert-manager/cert-manager/issues/9347): a
		// selector matching unlabelled Secrets turned every List into
		// one API request per Secret in the namespace. Fetch all of
		// them with a single live LIST instead, and re-filter it by
		// the selector: a metadata LIST returns every non-cert-manager
		// Secret in the namespace, while the caller asked for a
		// specific selector.
		//
		// Both cache lookups above are cluster-wide, so key the set by
		// NamespacedName: a name-only set lets a metadata match in another
		// namespace pull in the same-named Secret from this namespace.
		metadataSecretsSet := sets.New[types.NamespacedName]()
		for _, secretMeta := range metadataSecrets {
			metadataSecretsSet.Insert(types.NamespacedName{Namespace: secretMeta.Namespace, Name: secretMeta.Name})
		}

		// Push the selector to the apiserver: an empty ListOptions is a
		// quorum read of every Secret in the namespace with full data,
		// including the cert-manager-labelled ones already served from the
		// typed cache, and all of it would be thrown away client-side. The
		// client-side re-filter below stays as a guard.
		apiserverSecrets, err := snl.typedClient.Secrets(snl.namespace).List(snl.ctx, metav1.ListOptions{LabelSelector: selector.String()})
		if err != nil {
			log.Error(err, "error listing Secrets from kube apiserver")
			return nil, fmt.Errorf("error listing Secrets from kube apiserver: %w", err)
		}
		for i := range apiserverSecrets.Items {
			secret := apiserverSecrets.Items[i]
			if !selector.Matches(labels.Set(secret.Labels)) {
				continue
			}
			key := types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}
			if !metadataSecretsSet.Has(key) {
				continue
			}
			if _, ok := matchingSecretsMap[key]; ok {
				// A Secret in both caches is the internal error the user is
				// asked to report; the typed-cache copy is overwritten below
				// with the apiserver one.
				log.Info(fmt.Sprintf("warning: possible internal error: stale cache: secret found both in typed cache and in partial cache: %s", pleaseOpenIssue), "secret", key)
			}
			// Copy the match rather than pointing into apiserverSecrets.Items:
			// a caller holding one Secret would otherwise keep every Secret in
			// the namespace, with data, reachable.
			secretCopy := secret.DeepCopy()
			matchingSecretsMap[key] = secretCopy
		}
	}

	matchingSecrets := make([]*corev1.Secret, 0)
	for _, val := range matchingSecretsMap {
		matchingSecrets = append(matchingSecrets, val)
	}
	return matchingSecrets, nil
}
