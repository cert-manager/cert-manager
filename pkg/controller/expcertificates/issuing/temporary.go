/*
Copyright 2020 The Jetstack cert-manager contributors.

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
	"math/big"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/controller/expcertificates/internal/secretsmanager"
	"github.com/jetstack/cert-manager/pkg/controller/expcertificates/trigger/policies"
	utilpki "github.com/jetstack/cert-manager/pkg/util/pki"
)

// staticTemporarySerialNumber is a fixed serial number we use for temporary certificates
const staticTemporarySerialNumber = 0x1234567890

var TemporaryCertificatePolicyChain = policies.Chain{
	policies.SecretDoesNotExist,
	policies.SecretHasData,
	policies.SecretPublicKeysMatch,
}

// ensureTemporaryCertificate will create a temporary certificate and store it
// into the target Secret if:
// - The temporary certificate annotation is present
// - The target Secret does not exist yet, or the certificate/key data there is not valid
// - If the Certificate/Key pair does not match the 'NextPrivateKey'
func (c *controller) ensureTemporaryCertificate(ctx context.Context, crt *cmapi.Certificate, pkData []byte) error {
	// If certificate does not have temporary certificate annotation, do nothing
	if !certificateHasTemporaryCertificateAnnotation(crt) {
		return nil
	}

	// Attempt to fetch the Secret being managed but tolerate NotFound errors.
	secret, err := c.secretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	input := policies.Input{Secret: secret}
	// If the target Secret exists with a signed certificate and matching private
	// key which is the same as the desired, do not issue.
	_, _, invalid := TemporaryCertificatePolicyChain.Evaluate(input)
	if !invalid && bytes.Equal(input.Secret.Data[corev1.TLSPrivateKeyKey], pkData) {
		return nil
	}

	// Issue temporary certificate
	certData, err := c.localTemporarySigner(crt, pkData)
	if err != nil {
		return err
	}
	secretData := secretsmanager.SecretData{
		Certificate: certData,
		PrivateKey:  pkData,
	}
	if err := c.secretsManager.UpdateData(ctx, crt, secretData); err != nil {
		return err
	}

	message := "Issued temporary certificate"
	c.recorder.Event(crt, corev1.EventTypeNormal, "Issuing", message)

	return nil
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

// generateLocallySignedTemporaryCertificate signs a temporary certificate for
// the given certificate resource using a one-use temporary CA that is then
// discarded afterwards.
// This is to mitigate a potential attack against x509 certificates that use a
// predictable serial number and weak MD5 hashing algorithms.
// In practice, this shouldn't really be a concern anyway.
func generateLocallySignedTemporaryCertificate(crt *cmapi.Certificate, pkData []byte) ([]byte, error) {
	// generate a throwaway self-signed root CA
	caPk, err := utilpki.GenerateECPrivateKey(utilpki.ECCurve521)
	if err != nil {
		return nil, err
	}
	caCertTemplate, err := utilpki.GenerateTemplate(&cmapi.Certificate{
		Spec: cmapi.CertificateSpec{
			CommonName: "cert-manager.local",
			IsCA:       true,
		},
	})
	if err != nil {
		return nil, err
	}
	_, caCert, err := utilpki.SignCertificate(caCertTemplate, caCertTemplate, caPk.Public(), caPk)
	if err != nil {
		return nil, err
	}

	// sign a temporary certificate using the root CA
	template, err := utilpki.GenerateTemplate(crt)
	if err != nil {
		return nil, err
	}
	template.SerialNumber = big.NewInt(staticTemporarySerialNumber)

	signeeKey, err := utilpki.DecodePrivateKeyBytes(pkData)
	if err != nil {
		return nil, err
	}

	b, _, err := utilpki.SignCertificate(template, caCert, signeeKey.Public(), caPk)
	if err != nil {
		return nil, err
	}

	return b, nil
}
