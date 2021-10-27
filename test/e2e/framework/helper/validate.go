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

package helper

import (
	"context"
	"crypto"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework/helper/validation"
	"github.com/jetstack/cert-manager/test/e2e/framework/helper/validation/certificates"
	"github.com/jetstack/cert-manager/test/e2e/framework/helper/validation/certificatesigningrequests"
	"github.com/jetstack/cert-manager/test/e2e/framework/log"
)

// ValidateCertificate retrieves the issued certificate and runs all validation functions
func (h *Helper) ValidateCertificate(certificate *cmapi.Certificate, validations ...certificates.ValidationFunc) error {
	if len(validations) == 0 {
		validations = validation.DefaultCertificateSet()
	}

	secret, err := h.KubeClient.CoreV1().Secrets(certificate.Namespace).Get(context.TODO(), certificate.Spec.SecretName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	for _, fn := range validations {
		err := fn(certificate, secret)
		if err != nil {
			log.Logf("Certificate:\n")
			h.describeCMObject(certificate)

			log.Logf("Secret:\n")
			h.describeKubeObject(secret)

			return err
		}
	}

	return nil
}

// ValidateCertificateSigningRequest retrieves the issued certificate and runs all validation functions
func (h *Helper) ValidateCertificateSigningRequest(name string, key crypto.Signer, validations ...certificatesigningrequests.ValidationFunc) error {
	if len(validations) == 0 {
		validations = validation.DefaultCertificateSigningRequestSet()
	}
	csr, err := h.KubeClient.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	for _, fn := range validations {
		err := fn(csr, key)
		if err != nil {
			return err
		}
	}

	return nil
}
