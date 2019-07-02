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

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

func (c *CA) Sign(ctx context.Context, cr *v1alpha1.CertificateRequest) (*issuer.IssueResponse, error) {
	log := logf.FromContext(ctx, "sign")

	// get a copy of the CA certificate named on the Issuer
	caCerts, caKey, err := kube.SecretTLSKeyPair(ctx, c.secretsLister, c.resourceNamespace, c.issuer.GetSpec().CA.SecretName)
	if err != nil {
		log := logf.WithRelatedResourceName(log, c.issuer.GetSpec().CA.SecretName, c.resourceNamespace, "Secret")
		log.Info("error getting signing CA for Issuer")

		// We're fine to return errors here and later since upon a retry the issuer
		// will be marked as 'not ready' - therefore this codepath wont be reached
		// again
		return nil, err
	}

	template, err := pki.GenerateTemplateFromCertificateRequest(cr)
	if err != nil {
		log.Error(err, "error generating certificate template")
		c.Recorder.Eventf(cr, corev1.EventTypeWarning, "ErrorSigning", "Error generating certificate template: %v", err)
		return nil, err
	}

	resp, err := pki.SignCSRTemplate(caCerts, caKey, template)
	if err != nil {
		log.Error(err, "error signing certificate")
		c.Recorder.Eventf(cr, corev1.EventTypeWarning, "ErrorSigning", "Error signing certificate: %v", err)
		return nil, err
	}

	log.Info("certificate issued")

	return resp, nil
}
