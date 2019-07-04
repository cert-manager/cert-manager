/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package ca

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	reasonPending         = "Pending"
	reasonErrorPrivateKey = "ErrorPrivateKey"
	reasonErrorCA         = "ErrorCA"
	reasonErrorSigning    = "ErrorSigning"
)

// Issue will issue a certificate using the CA issuer contained in CA.
// It uses the 'Ready' status condition to convey the majority of failures, and
// treats them all as errors to be retried.
// If there are any failures, they are likely caused by missing or invalid
// supporting resources, and to ensure we re-attempt issuance when these resources
// are fixed, it always returns an error on any failure.
func (c *CA) Issue(ctx context.Context, crt *v1alpha1.Certificate) (*issuer.IssueResponse, error) {
	log := logf.FromContext(ctx, "issue")
	log = logf.WithRelatedResourceName(log, crt.Spec.SecretName, crt.Namespace, "Secret")

	// get a copy of the existing/currently issued Certificate's private key
	signeeKey, err := kube.SecretTLSKey(ctx, c.secretsLister, crt.Namespace, crt.Spec.SecretName)
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		log.Info("generating new private key")
		// if one does not already exist, generate a new one
		signeeKey, err = pki.GeneratePrivateKeyForCertificate(crt)
		if err != nil {
			log.Error(err, "error generating private key")
			c.Recorder.Eventf(crt, corev1.EventTypeWarning, "PrivateKeyError", "Error generating certificate private key: %v", err)
			// don't trigger a retry. An error from this function implies some
			// invalid input parameters, and retrying without updating the
			// resource will not help.
			return nil, nil
		}
	}
	if err != nil {
		log.Error(err, "error getting private key for certificate")
		return nil, err
	}

	// extract the public component of the key
	signeePublicKey, err := pki.PublicKeyForPrivateKey(signeeKey)
	if err != nil {
		log.Error(err, "error getting public key from private key")
		return nil, err
	}

	// get a copy of the CA certificate named on the Issuer
	caCerts, caKey, err := kube.SecretTLSKeyPair(ctx, c.secretsLister, c.resourceNamespace, c.issuer.GetSpec().CA.SecretName)
	if err != nil {
		log := logf.WithRelatedResourceName(log, c.issuer.GetSpec().CA.SecretName, c.resourceNamespace, "Secret")
		log.Info("error getting signing CA for Issuer")
		return nil, err
	}

	// generate a x509 certificate template for this Certificate
	template, err := pki.GenerateTemplate(crt)
	if err != nil {
		log.Error(err, "error generating certificate template")
		c.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Error generating certificate template: %v", err)
		return nil, err
	}

	template.PublicKey = signeePublicKey

	resp, err := pki.SignCSRTemplate(caCerts, caKey, template)
	if err != nil {
		log.Error(err, "error signing certificate")
		c.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Error signing certificate: %v", err)
	}

	// Encode output private key and CA cert ready for return
	keyPem, err := pki.EncodePrivateKey(signeeKey, crt.Spec.KeyEncoding)
	if err != nil {
		log.Error(err, "error encoding private key")
		c.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorPrivateKey", "Error encoding private key: %v", err)
		return nil, err
	}
	resp.PrivateKey = keyPem

	log.Info("certificate issued")

	return resp, nil
}
