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
	corev1 "k8s.io/api/core/v1"
	certificatesv1 "k8s.io/client-go/informers/certificates/v1"
	networkingv1informers "k8s.io/client-go/informers/networking/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

// This file contains common informers functionality such as shared interfaces
// The interfaces defined here are mostly a subset of similar interfaces upstream.
// Defining our own instead of reusing the upstream ones allows us to:
// - create smaller interfaces that don't have methods that our control loops don't need (thus avoid defining unnecessary methods in implementations)
// - swap embedded upstream interfaces for our own ones

var secretsGVR = corev1.SchemeGroupVersion.WithResource("secrets")

const pleaseOpenIssue = "Please report this by opening an issue with this error and cert-manager controller logs and stack trace https://github.com/cert-manager/cert-manager/issues/new/choose"

// KubeSharedInformerFactory represents a subset of methods in
// informers.sharedInformerFactory. It allows us to use a wrapper around
// informers.sharedInformerFactory to enforce particular custom informers for
// certain types, for example a filtered informer for Secrets If you need to
// start watching a new core type, add a method that returns an informer for
// that type here. If you don't need special filters, make it return an informer
// from baseFactory
type KubeInformerFactory interface {
	Start(<-chan struct{})
	WaitForCacheSync(<-chan struct{}) map[string]bool
	Ingresses() networkingv1informers.IngressInformer
	Secrets() SecretInformer
	CertificateSigningRequests() certificatesv1.CertificateSigningRequestInformer
}

// SecretInformer is like client-go SecretInformer
// https://github.com/kubernetes/client-go/blob/release-1.26/informers/core/v1/secret.go#L35-L40
// but embeds our own interfaces with a smaller subset of methods.
type SecretInformer interface {
	// Informer ensures that an Informer has been initialized and returns the initialized informer.
	Informer() Informer
	// Lister returns a lister for the initialized informer. It will also ensure that the informer exists.
	Lister() SecretLister
}

// SecretLister is a subset of client-go SecretLister functionality https://github.com/kubernetes/client-go/blob/release-1.26/listers/core/v1/secret.go#L28-L37
type SecretLister interface {
	// Secrets returns a namespace secrets getter/lister
	Secrets(namespace string) corev1listers.SecretNamespaceLister
}

// Informer is a subset of client-go SharedIndexInformer https://github.com/kubernetes/client-go/blob/release-1.26/tools/cache/shared_informer.go#L35-L211
type Informer interface {
	// AddEventHandler allows the reconcile loop to register an event handler so
	// it gets triggered when the informer has a new event
	AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error)
	// HasSynced returns true if the informer's cache has synced (at least
	// one LIST has been performed)
	HasSynced() bool
}
