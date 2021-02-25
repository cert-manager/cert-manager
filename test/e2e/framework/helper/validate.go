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

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/validations"
)

// ValidationFunc describes a certificate validation helper function
type ValidationFunc func(certificate *cmapi.Certificate, secret *v1.Secret) error

func (h *Helper) DefaultValidationSet() []ValidationFunc {
	return []ValidationFunc{
		validations.Expect2Or3KeysInSecret,
		validations.ExpectCertificateDNSNamesToMatch,
		validations.ExpectCertificateOrganizationToMatch,
		validations.ExpectCertificateURIsToMatch,
		validations.ExpectCorrectTrustChain,
		validations.ExpectEmailsToMatch,
		validations.ExpectValidAnnotations,
		validations.ExpectValidCertificate,
		validations.ExpectValidCommonName,
		validations.ExpectValidNotAfterDate,
		validations.ExpectValidPrivateKeyData,
	}
}

func (h *Helper) ValidationSetForUnsupportedFeatureSet(fs featureset.FeatureSet) []ValidationFunc {
	// basics
	out := []ValidationFunc{
		validations.Expect2Or3KeysInSecret,
		validations.ExpectCertificateDNSNamesToMatch,
		validations.ExpectCertificateOrganizationToMatch,
		validations.ExpectValidAnnotations,
		validations.ExpectValidCertificate,
		validations.ExpectValidCommonName,
		validations.ExpectValidNotAfterDate,
		validations.ExpectValidPrivateKeyData,
	}

	if !fs.Contains(featureset.URISANsFeature) {
		out = append(out, validations.ExpectCertificateURIsToMatch)
	}

	if !fs.Contains(featureset.EmailSANsFeature) {
		out = append(out, validations.ExpectEmailsToMatch)
	}

	if !fs.Contains(featureset.SaveCAToSecret) {
		out = append(out, validations.ExpectCorrectTrustChain)
	}

	return out
}

// ValidateCertificate retrieves the issued certificate and runs all validation functions
func (h *Helper) ValidateCertificate(ns, name string, validations ...ValidationFunc) error {
	if len(validations) == 0 {
		validations = h.DefaultValidationSet()
	}
	certificate, err := h.CMClient.CertmanagerV1().Certificates(ns).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	secret, err := h.KubeClient.CoreV1().Secrets(certificate.Namespace).Get(context.TODO(), certificate.Spec.SecretName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	for _, fn := range validations {
		err := fn(certificate, secret)
		if err != nil {
			return err
		}
	}

	return nil
}
