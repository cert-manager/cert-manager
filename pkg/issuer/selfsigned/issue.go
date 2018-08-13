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

package selfsigned

import (
	"context"
	"crypto"
	"time"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	errorGetCertKeyPair   = "ErrGetKey"
	errorIssueCert        = "ErrIssueCert"
	errorEncodePrivateKey = "ErrEncodePrivateKey"

	successCertIssued = "CertIssueSuccess"

	messageErrorGetCertKeyPair   = "Error getting keypair for certificate: "
	messageErrorIssueCert        = "Error issuing TLS certificate: "
	messageErrorEncodePrivateKey = "Error encoding private key: "

	messageCertIssued = "Certificate issued successfully"
)

const (
	// certificateDuration of 1 year
	certificateDuration = time.Hour * 24 * 365
	defaultOrganization = "cert-manager"
)

func (c *SelfSigned) Issue(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	signeeKey, err := kube.SecretTLSKey(c.secretsLister, crt.Namespace, crt.Spec.SecretName)

	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		signeeKey, err = pki.GeneratePrivateKeyForCertificate(crt)
	}

	if err != nil {
		s := messageErrorGetCertKeyPair + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorGetCertKeyPair, s, false)
		return nil, nil, err
	}

	certPem, err := c.obtainCertificate(crt, signeeKey)

	if err != nil {
		s := messageErrorIssueCert + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueCert, s, false)
		return nil, nil, err
	}

	crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, successCertIssued, messageCertIssued, true)

	keyPem, err := pki.EncodePrivateKey(signeeKey)
	if err != nil {
		s := messageErrorEncodePrivateKey + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorEncodePrivateKey, s, false)
		return nil, nil, err
	}

	return keyPem, certPem, nil
}

func (c *SelfSigned) obtainCertificate(crt *v1alpha1.Certificate, privateKey crypto.PrivateKey) ([]byte, error) {
	publicKey, err := pki.PublicKeyForPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	template, err := pki.GenerateTemplate(c.issuer, crt, nil)
	if err != nil {
		return nil, err
	}

	crtPem, _, err := pki.SignCertificate(template, template, publicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return crtPem, nil
}
