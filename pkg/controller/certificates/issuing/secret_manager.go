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
	"context"
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/cert-manager/cert-manager/internal/controller/certificates/policies"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/issuing/internal"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
)

// ensureSecretData ensures that the Certificate's Secret is up to date with
// non-issuing condition related data.
// Reconciles over the Certificate's SecretTemplate, and
// AdditionalOutputFormats.
func (c *controller) ensureSecretData(ctx context.Context, log logr.Logger, crt *cmapi.Certificate) error {
	// Retrieve the Secret which is associated with this Certificate.
	secret, err := c.secretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)

	// Secret doesn't exist so we can't do anything. The Certificate will be
	// marked for a re-issuance and the resulting Secret will be evaluated again.
	if apierrors.IsNotFound(err) {
		log.V(logf.DebugLevel).Info("secret not found", "error", err.Error())
		return nil
	}

	// This error is transient, return error to be retried on the rate limiting
	// queue.
	if err != nil {
		return err
	}

	log = log.WithValues("secret", secret.Name)

	// If there is no certificate or private key data available at the target
	// Secret then exit early. The absence of these keys should cause an issuance
	// of the Certificate, so there is no need to run post issuance checks.
	if secret.Data == nil ||
		len(secret.Data[corev1.TLSCertKey]) == 0 ||
		len(secret.Data[corev1.TLSPrivateKeyKey]) == 0 {
		log.V(logf.DebugLevel).Info("secret doesn't contain both certificate and private key data",
			"cert_data_len", len(secret.Data[corev1.TLSCertKey]), "key_data_len", len(secret.Data[corev1.TLSPrivateKeyKey]))
		return nil
	}

	// Check whether the Certificate's Secret has correct output format and
	// metadata.
	reason, message, isViolation := c.postIssuancePolicyChain.Evaluate(policies.Input{
		Certificate: crt,
		Secret:      secret,
	})

	certificateHash := secret.Annotations[cmapi.CertificateHashAnnotationKey]
	if certificateHash == "" {
		log.V(logf.DebugLevel).Info("secret doesn't contain certificate hash annotation")

		// If the certificate hash is not set, we try to calculate a hash from
		// the certificate data and set it on the secret. We only do this after
		// we verified that the certificate is Ready, so we don't set the wrong
		// hash on a secret that is not up to date.
		// This is to ensure that all secrets have the certificate hash
		// annotation and we can remove the fallback chain in a future release.

		readyCondition := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionReady)
		issuingCondition := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionIssuing)

		// If the certificate's ready condition is not up-to-date, we do not change the
		// certificate hash annotation. Also, if the certificate is already being issued,
		// we do not need to update the certificate hash annotation (as it will be updated once
		// the certificate is issued).
		if readyCondition != nil && readyCondition.ObservedGeneration != crt.Generation {
			// Leave the certificate hash annotation empty, so that the next time the
			// certificate is reconciled, we will try to set the certificate hash again.
		} else if issuingCondition != nil && issuingCondition.Status == cmmeta.ConditionTrue {
			// Leave the certificate hash annotation empty, so that the next time the
			// certificate is reconciled, we will try to set the certificate hash again.
		} else if readyCondition == nil || readyCondition.Status != cmmeta.ConditionTrue {
			log.V(logf.DebugLevel).Info("certificate is not ready, setting the certificate hash to a mismatching value")

			certificateHash = "secret-not-up-to-date"
		} else {
			hash, err := utilpki.CertificateInfoHash(crt)
			if err != nil {
				return fmt.Errorf("failed to compute certificate hash: %w", err)
			}

			certificateHash = hash
		}
	}

	data := internal.SecretData{
		PrivateKey:      secret.Data[corev1.TLSPrivateKeyKey],
		Certificate:     secret.Data[corev1.TLSCertKey],
		CA:              secret.Data[cmmeta.TLSCAKey],
		CertificateHash: certificateHash,
		CertificateName: secret.Annotations[cmapi.CertificateNameKey],
		IssuerName:      secret.Annotations[cmapi.IssuerNameAnnotationKey],
		IssuerKind:      secret.Annotations[cmapi.IssuerKindAnnotationKey],
		IssuerGroup:     secret.Annotations[cmapi.IssuerGroupAnnotationKey],
	}

	if isViolation {
		switch reason {
		case policies.InvalidCertificate, policies.ManagedFieldsParseError:
			// An error here indicates that the managed fields are malformed and the
			// decoder doesn't understand the managed fields on the Secret, or the
			// signed certificate data could not be decoded. There is nothing more the
			// controller can do here, so we exit nil so this controller doesn't end in
			// an infinite loop.
			log.Error(errors.New(message), "failed to determine whether the SecretTemplate matches Secret")
			return nil
		default:

			// Here the Certificate need to be re-reconciled.
			log.Info("applying Secret data", "message", message)
			return c.secretsUpdateData(ctx, crt, data)
		}
	}

	// No Secret violations, nothing to do.

	return nil
}
