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

package issuing

import (
	"bytes"
	"context"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/structured-merge-diff/v4/fieldpath"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/controller/certificates/internal/secretsmanager"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

// ensureSecretData ensures that the Certificate's Secret is up to date with
// non-issuing condition related data. Currently only reconciles on Annotations
// and Labels from the Certificate's SecretTemplate.
func (c *controller) ensureSecretData(ctx context.Context, log logr.Logger, crt *cmapi.Certificate) error {
	dbg := log.V(logf.DebugLevel)

	// Retrieve the Secret which is associated with this Certificate.
	secret, err := c.secretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)

	// Secret doesn't exist so we can't do anything. The Certificate will be
	// marked for a re-issuance and the resulting Secret will be evaluated again.
	if apierrors.IsNotFound(err) {
		dbg.Info("secret not found", "error", err.Error())
		return nil
	}

	// This error is transient, return error to be retried on the rate limiting
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
		log.Info("mismatch between SecretTemplate and Secret, updating Secret annotations/labels")
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
	managedLabels, managedAnnotations := sets.NewString(), sets.NewString()

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
			managedLabels.Insert(strings.TrimPrefix(path.String(), "."))
		})
		annotations.Iterate(func(path fieldpath.Path) {
			managedAnnotations.Insert(strings.TrimPrefix(path.String(), "."))
		})
	}

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
		specMap    map[string]string
		managedSet sets.String
	}{
		{specMap: crt.Spec.SecretTemplate.Labels, managedSet: managedLabels},
		{specMap: crt.Spec.SecretTemplate.Annotations, managedSet: managedAnnotations},
	} {

		specSet := sets.NewString()
		for kSpec := range smap.specMap {
			specSet.Insert(kSpec)
		}

		if !specSet.Equal(smap.managedSet) {
			return false, nil
		}
	}

	return true, nil
}
