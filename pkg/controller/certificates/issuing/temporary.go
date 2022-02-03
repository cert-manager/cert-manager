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
	"crypto"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/cert-manager/cert-manager/internal/controller/certificates/policies"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/issuing/internal"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
)

// ensureTemporaryCertificate will create a temporary certificate and store it
// into the target Secret if:
// - The temporary certificate annotation is present
// - The target Secret does not exist yet, or the certificate/key data there is not valid
// - If the Certificate/Key pair does not match the 'NextPrivateKey'
// Returns true is a temporary certificate was issued
func (c *controller) ensureTemporaryCertificate(ctx context.Context, crt *cmapi.Certificate, pk crypto.Signer) (bool, error) {
	crt = crt.DeepCopy()
	if crt.Spec.PrivateKey == nil {
		crt.Spec.PrivateKey = &cmapi.CertificatePrivateKey{}
	}

	// If certificate does not have temporary certificate annotation, do nothing
	if !certificateHasTemporaryCertificateAnnotation(crt) {
		return false, nil
	}

	// Attempt to fetch the Secret being managed but tolerate NotFound errors.
	secret, err := c.secretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)
	if err != nil && !apierrors.IsNotFound(err) {
		return false, err
	}
	input := policies.Input{Secret: secret}
	// If the target Secret exists with a signed certificate and matching private
	// key, do not issue.
	if _, _, invalid := policies.NewTemporaryCertificatePolicyChain().Evaluate(input); !invalid {
		return false, nil
	}

	// Issue temporary certificate
	pkData, err := utilpki.EncodePrivateKey(pk, crt.Spec.PrivateKey.Encoding)
	if err != nil {
		return false, err
	}
	certData, err := c.localTemporarySigner(crt, pkData)
	if err != nil {
		return false, err
	}
	secretData := internal.SecretData{
		Certificate: certData,
		PrivateKey:  pkData,
	}
	if err := c.secretsUpdateData(ctx, crt, secretData); err != nil {
		return false, err
	}

	c.recorder.Event(crt, corev1.EventTypeNormal, "Issuing", "Issued temporary certificate")

	return true, nil
}

func certificateHasTemporaryCertificateAnnotation(crt *cmapi.Certificate) bool {
	if crt.Annotations == nil {
		return false
	}

	if val, ok := crt.Annotations[cmapi.IssueTemporaryCertificateAnnotation]; ok && val == "true" {
		return true
	}

	return false
}
