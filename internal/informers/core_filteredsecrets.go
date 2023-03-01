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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
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

	r, err = labels.NewRequirement(cmapi.PartOfCertManagerControllerLabelKey, selection.DoesNotExist, make([]string, 0))
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
		typedInformerFactory: kubeinformers.NewSharedInformerFactory(typedClient, resync),
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
	// WaitForCacheSync are valid map key arguments in generics- they aren't
	// comparable types.
	for key, val := range typedCaches {
		caches[key.String()] = val
	}
	for key, val := range partialMetaCaches {
		caches[key.String()] = val
	}
	return caches
}

func (bf *filteredSecretsFactory) Pods() corev1informers.PodInformer {
	return bf.typedInformerFactory.Core().V1().Pods()
}

func (bf *filteredSecretsFactory) Services() corev1informers.ServiceInformer {
	return bf.typedInformerFactory.Core().V1().Services()
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
	// TODO: set any possible transforms
	metadataInformer := f.metadataInformerFactory.ForResource(secretsGVR).Informer()
	// TODO: set transform on metadataInformer to remove last applied annotation etc
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
	// TODO: add link
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
	// TODO: add link
	// Go recommends to not store context in
	// structs, but here we have no other way as we need to use root context inside
	// Get whose signature is defined upstream and does not accept context
	ctx context.Context
}

func (snl *secretNamespaceLister) Get(name string) (*corev1.Secret, error) {
	log := logf.FromContext(snl.ctx)
	log = log.WithValues("secret", name, "namespace", snl.namespace)
	// TODO: debug print
	log.Info("Getting secret from cache")
	var secretFoundInTypedCache, secretFoundInMetadataCache bool
	secret, err := snl.typedLister.Secrets(snl.namespace).Get(name)
	if err == nil {
		secretFoundInTypedCache = true
	}

	if err != nil && !apierrors.IsNotFound(err) {
		log.Error(err, "error getting secret from typed cache")
		return nil, fmt.Errorf("error retrieving secret from the typed cache: %w", err)
	}
	_, partialMetadataGetErr := snl.partialMetadataLister.Namespace(snl.namespace).Get(name)
	if partialMetadataGetErr == nil {
		// TODO: debug line
		log.Info("Secret found in partial metadata cache, getting it from kube apiserver")
		secretFoundInMetadataCache = true
	}

	if partialMetadataGetErr != nil && !apierrors.IsNotFound(partialMetadataGetErr) {
		return nil, fmt.Errorf("error retrieving object from partial object metadata cache: %w", err)
	}

	if secretFoundInMetadataCache && secretFoundInTypedCache {
		// TODO: this error message should be made into something that makes sense to users if they see it
		log.Info(fmt.Sprintf("warning: possible internal error: stale cache: secret found both in typed cache and in partial cache: %s", pleaseOpenIssue), "secret name")
		return snl.typedClient.Secrets(snl.namespace).Get(snl.ctx, name, metav1.GetOptions{})
	}

	if secretFoundInTypedCache {
		// TODO: remove debug line
		log.Info("secret found in typed cache, returning the cached version")
		return secret, nil
	}

	if secretFoundInMetadataCache {
		return snl.typedClient.Secrets(snl.namespace).Get(snl.ctx, name, metav1.GetOptions{})
	}

	// TODO: debug line
	log.Info("secret neither in typed nor metadata cache")
	// TODO: we want to return apierrors.ErrNotFound here, but which one?
	return nil, partialMetadataGetErr
}

func (snl *secretNamespaceLister) List(selector labels.Selector) ([]*corev1.Secret, error) {
	log := logf.FromContext(snl.ctx)
	log = log.WithValues("secrets namespace", snl.namespace, "secrets selector", selector.String())
	matchingSecretsMap := make(map[string]*corev1.Secret)
	typedSecrets, err := snl.typedLister.List(selector)
	if err != nil {
		log.Error(err, "error listing Secrets from typed cache")
		return nil, err
	}
	for _, secret := range typedSecrets {
		key := types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}.String()
		matchingSecretsMap[key] = secret
	}
	metadataSecrets, err := snl.partialMetadataLister.List(selector)
	if err != nil {
		log.Error(err, "error listing Secrets from metadata only cache")
		return nil, err
	}
	for _, secretMeta := range metadataSecrets {
		unstructuredObj, err := objectToUnstructured(secretMeta)
		if err != nil {
			log.Error(err, "error converting runtime object to unstructured")
			return nil, err
		}
		name := unstructuredObj.GetName()
		key := types.NamespacedName{Namespace: snl.namespace, Name: name}.String()
		if _, ok := matchingSecretsMap[key]; ok {
			log.Info(fmt.Sprintf("warning: possible internal error: stale cache: secret found both in typed cache and in partial cache: %s", pleaseOpenIssue), "secret name", name)
			// do nothing- use object from typed cache
		}
		secret, err := snl.typedClient.Secrets(snl.namespace).Get(snl.ctx, name, metav1.GetOptions{})
		if err != nil {
			log.Error(err, "error retrieving secret from kube apiserver", "secret name", name)
			return nil, err
		}
		matchingSecretsMap[key] = secret
	}

	matchingSecrets := make([]*corev1.Secret, 0)
	for _, val := range matchingSecretsMap {
		matchingSecrets = append(matchingSecrets, val)
	}
	return matchingSecrets, nil
}

func objectToUnstructured(obj runtime.Object) (*unstructured.Unstructured, error) {
	unstructuredContent, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	u := &unstructured.Unstructured{}
	u.SetUnstructuredContent(unstructuredContent)
	u.SetGroupVersionKind(obj.GetObjectKind().GroupVersionKind())
	return u, nil
}
