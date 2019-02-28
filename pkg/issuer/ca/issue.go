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
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
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
	// get a copy of the existing/currently issued Certificate's private key
	signeeKey, err := kube.SecretTLSKey(c.secretsLister, crt.Namespace, crt.Spec.SecretName)
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		// if one does not already exist, generate a new one
		signeeKey, err = pki.GeneratePrivateKeyForCertificate(crt)
		if err != nil {
			c.Recorder.Eventf(crt, corev1.EventTypeWarning, "PrivateKeyError", "Error generating certificate private key: %v", err)
			// don't trigger a retry. An error from this function implies some
			// invalid input parameters, and retrying without updating the
			// resource will not help.
			return nil, nil
		}
	}
	if err != nil {
		klog.Errorf("Error getting private key %q for certificate: %v", crt.Spec.SecretName, err)
		return nil, err
	}

	// extract the public component of the key
	signeePublicKey, err := pki.PublicKeyForPrivateKey(signeeKey)
	if err != nil {
		klog.Errorf("Error getting public key from private key: %v", err)
		return nil, err
	}

	// get a copy of the CA certificate named on the Issuer
	caCerts, caKey, err := kube.SecretTLSKeyPair(c.secretsLister, c.resourceNamespace, c.issuer.GetSpec().CA.SecretName)
	if err != nil {
		klog.Errorf("Error getting signing CA for Issuer: %v", err)
		return nil, err
	}

	// generate a x509 certificate template for this Certificate
	template, err := pki.GenerateTemplate(crt)
	if err != nil {
		c.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Error signing certificate: %v", err)
		return nil, err
	}

	caCert := caCerts[0]

	// sign and encode the certificate
	certPem, _, err := pki.SignCertificate(template, caCert, signeePublicKey, caKey)
	if err != nil {
		c.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Error signing certificate: %v", err)
		return nil, err
	}

	// encode the chain
	// TODO: replace caCerts with caCerts[1:]?
	chainPem, err := pki.EncodeX509Chain(caCerts)
	if err != nil {
		return nil, err
	}

	certPem = append(certPem, chainPem...)

	// Encode output private key and CA cert ready for return
	keyPem, err := pki.EncodePrivateKey(signeeKey)
	if err != nil {
		c.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorPrivateKey", "Error encoding private key: %v", err)
		return nil, err
	}

	// encode the CA certificate to be bundled in the output
	caPem, err := pki.EncodeX509(caCerts[0])
	if err != nil {
		c.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Error encoding certificate: %v", err)
		return nil, err
	}

	return &issuer.IssueResponse{
		PrivateKey:  keyPem,
		Certificate: certPem,
		CA:          caPem,
	}, nil
}
