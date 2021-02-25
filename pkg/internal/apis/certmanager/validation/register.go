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

package validation

import (
	"github.com/cert-manager/cert-manager/pkg/internal/api/validation"
	cmapi "github.com/cert-manager/cert-manager/pkg/internal/apis/certmanager"
)

func AddToValidationRegistry(reg *validation.Registry) error {
	if err := reg.AddValidateFunc(&cmapi.Certificate{}, ValidateCertificate); err != nil {
		return err
	}
	if err := reg.AddValidateUpdateFunc(&cmapi.Certificate{}, ValidateUpdateCertificate); err != nil {
		return err
	}

	if err := reg.AddValidateFunc(&cmapi.CertificateRequest{}, ValidateCertificateRequest); err != nil {
		return err
	}
	if err := reg.AddValidateUpdateFunc(&cmapi.CertificateRequest{}, ValidateUpdateCertificateRequest); err != nil {
		return err
	}

	if err := reg.AddValidateFunc(&cmapi.ClusterIssuer{}, ValidateClusterIssuer); err != nil {
		return err
	}
	if err := reg.AddValidateUpdateFunc(&cmapi.ClusterIssuer{}, ValidateUpdateClusterIssuer); err != nil {
		return err
	}

	if err := reg.AddValidateFunc(&cmapi.Issuer{}, ValidateIssuer); err != nil {
		return err
	}
	if err := reg.AddValidateUpdateFunc(&cmapi.Issuer{}, ValidateUpdateIssuer); err != nil {
		return err
	}
	return nil
}
