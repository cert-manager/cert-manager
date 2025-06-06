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
	"k8s.io/apimachinery/pkg/types"
	kerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/validation"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/validation/certificaterequests"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/validation/certificates"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/validation/certificatesigningrequests"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/log"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// ValidateCertificate retrieves the issued certificate and runs all validation functions
func (h *Helper) ValidateCertificate(certificate *cmapi.Certificate, validations ...certificates.ValidationFunc) error {
	if len(validations) == 0 {
		validations = validation.CertificateSetForUnsupportedFeatureSet(featureset.NewFeatureSet())
	}

	secret, err := h.KubeClient.CoreV1().Secrets(certificate.Namespace).Get(context.TODO(), certificate.Spec.SecretName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	for _, fn := range validations {
		err := fn(certificate, secret)
		if err != nil {
			errs := []error{err}
			log.Logf("Certificate:\n")
			errs = append(errs, h.describeCMObject(certificate))

			log.Logf("Secret:\n")
			errs = append(errs, h.describeKubeObject(secret))

			return kerrors.NewAggregate(errs)
		}
	}

	return nil
}

// ValidateCertificateRequest retrieves the issued certificate and runs all validation functions
func (h *Helper) ValidateCertificateRequest(name types.NamespacedName, key crypto.Signer, validations ...certificaterequests.ValidationFunc) error {
	if len(validations) == 0 {
		validations = validation.CertificateRequestSetForUnsupportedFeatureSet(featureset.NewFeatureSet())
	}

	cr, err := h.CMClient.CertmanagerV1().CertificateRequests(name.Namespace).Get(context.TODO(), name.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	for _, fn := range validations {
		err := fn(cr, key)
		if err != nil {
			return err
		}
	}

	return nil
}

// ValidateCertificateSigningRequest retrieves the issued certificate and runs all validation functions
func (h *Helper) ValidateCertificateSigningRequest(name string, key crypto.Signer, validations ...certificatesigningrequests.ValidationFunc) error {
	if len(validations) == 0 {
		validations = validation.CertificateSigningRequestSetForUnsupportedFeatureSet(featureset.NewFeatureSet())
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
