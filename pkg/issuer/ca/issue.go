/*
Copyright 2018 The Jetstack cert-manager contributors.

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
	"crypto/x509"
	"fmt"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

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
func (c *CA) Issue(ctx context.Context, crt *v1alpha1.Certificate) (issuer.IssueResponse, error) {
	signeeKey, err := kube.SecretTLSKey(c.secretsLister, crt.Namespace, crt.Spec.SecretName)
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		signeeKey, err = pki.GeneratePrivateKeyForCertificate(crt)
		if err != nil {
			crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse,
				reasonErrorPrivateKey, fmt.Sprintf("Error generating private key for certificate: %v", err), false)
			return issuer.IssueResponse{}, err
		}
	}
	if err != nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse,
			reasonErrorPrivateKey, fmt.Sprintf("Error getting private key for certificate: %v", err), false)
		return issuer.IssueResponse{}, err
	}

	publicKey, err := pki.PublicKeyForPrivateKey(signeeKey)
	if err != nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse,
			reasonErrorPrivateKey, fmt.Sprintf("Error getting public key from private key: %v", err), false)
		return issuer.IssueResponse{}, err
	}

	caCert, err := kube.SecretTLSCert(c.secretsLister, c.resourceNamespace, c.issuer.GetSpec().CA.SecretName)
	if err != nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse,
			reasonErrorCA, fmt.Sprintf("Error getting signing CA: %v", err), false)
		return issuer.IssueResponse{}, err
	}

	certPem, err := c.obtainCertificate(crt, publicKey, caCert)
	if err != nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse,
			reasonErrorSigning, fmt.Sprintf("Error signing certificate: %v", err), false)
		return issuer.IssueResponse{}, err
	}

	// Encode output private key and CA cert ready for return
	keyPem, err := pki.EncodePrivateKey(signeeKey)
	if err != nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse,
			reasonErrorPrivateKey, fmt.Sprintf("Error encoding certificate private key: %v", err), false)
		return issuer.IssueResponse{}, err
	}

	caPem, err := pki.EncodeX509(caCert)
	if err != nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse,
			reasonErrorSigning, fmt.Sprintf("Error encoding certificate: %v", err), false)
		return issuer.IssueResponse{}, err
	}

	return issuer.IssueResponse{
		PrivateKey:  keyPem,
		Certificate: certPem,
		CA:          caPem,
	}, nil
}

func (c *CA) obtainCertificate(crt *v1alpha1.Certificate, signeeKey interface{}, signerCert *x509.Certificate) ([]byte, error) {
	commonName := crt.Spec.CommonName
	altNames := crt.Spec.DNSNames
	if len(commonName) == 0 && len(altNames) == 0 {
		return nil, fmt.Errorf("no domains specified on certificate")
	}

	signerKey, err := kube.SecretTLSKey(c.secretsLister, c.resourceNamespace, c.issuer.GetSpec().CA.SecretName)
	if err != nil {
		return nil, fmt.Errorf("error getting issuer private key: %s", err.Error())
	}

	template, err := pki.GenerateTemplate(c.issuer, crt, nil)
	if err != nil {
		return nil, err
	}

	crtPem, _, err := pki.SignCertificate(template, signerCert, signeeKey, signerKey)
	if err != nil {
		return nil, err
	}

	return crtPem, nil
}
