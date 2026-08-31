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
	corelisters "k8s.io/client-go/listers/core/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// IsNextPrivateKeySecret reports whether secret is one the keymanager
// controller created for crt: it must carry the
// `cert-manager.io/next-private-key` label and have crt as its controller.
//
// This is the invariant the keymanager maintains and every consumer of
// status.nextPrivateKeySecretName relies on, so it lives in one place.
func IsNextPrivateKeySecret(secret *corev1.Secret, crt *cmapi.Certificate) bool {
	return secret.Labels[cmapi.IsNextPrivateKeySecretLabelKey] == "true" && metav1.IsControlledBy(secret, crt)
}

// GetNextPrivateKeySecret returns the Secret named by
// crt.Status.NextPrivateKeySecretName, but only if that Secret is one that the
// keymanager controller created for this Certificate: it must carry the
// `cert-manager.io/next-private-key` label and have crt as its controller.
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
func GetNextPrivateKeySecret(lister corelisters.SecretNamespaceLister, crt *cmapi.Certificate) (*corev1.Secret, error) {
	if crt.Status.NextPrivateKeySecretName == nil || *crt.Status.NextPrivateKeySecretName == "" {
		return nil, apierrors.NewNotFound(corev1.Resource("secrets"), "")
	}

	name := *crt.Status.NextPrivateKeySecretName
	secret, err := lister.Get(name)
	if err != nil {
		return nil, err
	}

	if !IsNextPrivateKeySecret(secret, crt) {
		return nil, apierrors.NewNotFound(corev1.Resource("secrets"), name)
	}

	return secret, nil
}
