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

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/cert-manager/cert-manager/internal/controller/certificates/policies"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/issuing/internal"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
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

	log = log.WithValues("secret", secret.Name)

	var data internal.SecretData
	if secret.Data != nil {
		data = internal.SecretData{
			PrivateKey:  secret.Data[corev1.TLSPrivateKeyKey],
			Certificate: secret.Data[corev1.TLSCertKey],
			CA:          secret.Data[cmmeta.TLSCAKey],
		}
	}

	// Check whether the Certificate's Secret has correct output format and
	// metadata.
	reason, message, isViolation := c.postIssuancePolicyChain.Evaluate(policies.Input{
		Certificate: crt,
		Secret:      secret,
	})

	if isViolation {
		switch reason {
		case policies.InvalidCertificate, policies.ManagedFieldsParseError:
			//An error here indicates that the managed fields are malformed and the
			//decoder doesn't understand the managed fields on the Secret, or the
			//signed certificate data could not be decoded. There is nothing more the
			//controller can do here, so we exit nil so this controller doesn't end in
			//an infinite loop.
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
