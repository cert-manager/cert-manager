/*
Copyright 2026 The cert-manager Authors.

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

package certificates

import (
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/utils/ptr"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// IsNextPrivateKeySecret reports whether secret is one the keymanager
// controller created for crt: it must carry the
// `cert-manager.io/next-private-key` label, have crt as its controller, and
// not be the Secret named by spec.secretName.
//
// The last check is needed because spec.secretTemplate.labels can put the
// label on spec.secretName, and --enable-certificate-owner-ref gives that
// Secret the controller reference. Without it the keymanager would treat the
// served certificate Secret as a temporary private key Secret and delete it.
//
// Every consumer of status.nextPrivateKeySecretName relies on this check, so
// it lives in one place.
func IsNextPrivateKeySecret(secret *corev1.Secret, crt *cmapi.Certificate) bool {
	return secret.Name != crt.Spec.SecretName &&
		secret.Labels[cmapi.IsNextPrivateKeySecretLabelKey] == "true" &&
		metav1.IsControlledBy(secret, crt)
}

// NextPrivateKeySecretSelector narrows a Secret LIST to next private key
// Secrets. It must stay in the lister selector, and must not be folded into
// a predicate applied after the LIST.
//
// The SecretsFilteredCaching feature, which is on by default, replaces the
// Secret lister with one that serves a LIST from two caches: a typed cache of
// cert-manager's own Secrets, which are labeled, and a metadata-only cache of
// every other Secret in the namespace. The metadata cache stores no labels, so
// this selector matches nothing in it. A selector that does match there costs
// one live GET against the API server per Secret, on every reconcile.
var NextPrivateKeySecretSelector = labels.SelectorFromSet(labels.Set{
	cmapi.IsNextPrivateKeySecretLabelKey: "true",
})

// ListNextPrivateKeySecrets returns every Secret that IsNextPrivateKeySecret
// accepts for crt.
func ListNextPrivateKeySecrets(lister corelisters.SecretNamespaceLister, crt *cmapi.Certificate) ([]*corev1.Secret, error) {
	return ListSecretsMatchingPredicates(lister, NextPrivateKeySecretSelector, func(s *corev1.Secret) bool {
		return IsNextPrivateKeySecret(s, crt)
	})
}

// GetNextPrivateKeySecret returns the Secret named by
// crt.Status.NextPrivateKeySecretName, but only if IsNextPrivateKeySecret
// accepts it. An unset or empty name is reported as not found.
//
// The name alone must not be trusted. status.nextPrivateKeySecretName is
// writable by any principal with access to the certificates/status
// subresource, which is a weaker permission than reading Secrets in the
// namespace. Without this check, such a principal can name any Secret in the
// namespace and have its private key copied into spec.secretName.
//
// A Secret that exists but fails these checks is reported as not found, so
// that callers wait for the keymanager controller to reconcile the field back
// to a Secret it owns, exactly as they do when the Secret is absent.
//
// The lookup is a label-selected LIST rather than a GET by name so that a
// Secret the keymanager did not create is never read from the API server:
// the filtered lister answers a GET for an unlabeled Secret with a live
// request that returns the whole Secret, private key included.
func GetNextPrivateKeySecret(lister corelisters.SecretNamespaceLister, crt *cmapi.Certificate) (*corev1.Secret, error) {
	name := ptr.Deref(crt.Status.NextPrivateKeySecretName, "")
	if name == "" {
		return nil, apierrors.NewNotFound(corev1.Resource("secrets"), "")
	}

	secrets, err := ListSecretsMatchingPredicates(lister, NextPrivateKeySecretSelector, func(s *corev1.Secret) bool {
		return s.Name == name && IsNextPrivateKeySecret(s, crt)
	})
	if err != nil {
		return nil, err
	}
	if len(secrets) == 0 {
		return nil, apierrors.NewNotFound(corev1.Resource("secrets"), name)
	}
	return secrets[0], nil
}
