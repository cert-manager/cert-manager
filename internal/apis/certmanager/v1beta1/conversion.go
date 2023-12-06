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

package v1beta1

import (
	"k8s.io/apimachinery/pkg/conversion"

	"github.com/cert-manager/cert-manager/internal/apis/certmanager"
)

func Convert_v1beta1_CertificateSpec_To_certmanager_CertificateSpec(in *CertificateSpec, out *certmanager.CertificateSpec, s conversion.Scope) error {
	if err := autoConvert_v1beta1_CertificateSpec_To_certmanager_CertificateSpec(in, out, s); err != nil {
		return err
	}

	out.EmailAddresses = in.EmailSANs
	out.URIs = in.URISANs

	return nil
}

func Convert_certmanager_CertificateSpec_To_v1beta1_CertificateSpec(in *certmanager.CertificateSpec, out *CertificateSpec, s conversion.Scope) error {
	if err := autoConvert_certmanager_CertificateSpec_To_v1beta1_CertificateSpec(in, out, s); err != nil {
		return err
	}

	out.EmailSANs = in.EmailAddresses
	out.URISANs = in.URIs

	return nil
}
