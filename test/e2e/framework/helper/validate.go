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

package helper

import (
	"context"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ValidationFunc describes a certificate validation helper function
type ValidationFunc func(certificate *cmapi.Certificate, secret *v1.Secret) error

func (h *Helper) getValidationFuncsForFeatureSet() []ValidationFunc {
	h.
	return []ValidationFunc{}
}

// ValidateCertificate retreives the issued certificate and runs all validation functions
func (h *Helper) ValidateCertificate(ns, name string) error {
	certificate, err := h.CMClient.CertmanagerV1alpha2().Certificates(ns).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	secret, err := h.KubeClient.CoreV1().Secrets(certificate.Namespace).Get(context.TODO(), certificate.Spec.SecretName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	for _, fn := range h.getValidationFuncsForFeatureSet() {
		err := fn(certificate, secret)
		if err != nil {
			return err
		}
	}

	return nil
}
