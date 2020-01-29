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

package v1alpha2

import (
	"k8s.io/apimachinery/pkg/conversion"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
)

func Convert_v1alpha2_CertificateSpec_To_certmanager_CertificateSpec(in *v1alpha2.CertificateSpec, out *certmanager.CertificateSpec, s conversion.Scope) error {
	if err := autoConvert_v1alpha2_CertificateSpec_To_certmanager_CertificateSpec(in, out, s); err != nil {
		return err
	}

	if len(in.Organization) > 0 {
		if out.Subject == nil {
			out.Subject = &certmanager.X509Subject{}
		}

		out.Subject.Organizations = in.Organization
	}

	return nil
}

func Convert_certmanager_CertificateSpec_To_v1alpha2_CertificateSpec(in *certmanager.CertificateSpec, out *v1alpha2.CertificateSpec, s conversion.Scope) error {
	if err := autoConvert_certmanager_CertificateSpec_To_v1alpha2_CertificateSpec(in, out, s); err != nil {
		return err
	}

	if in.Subject != nil {
		out.Organization = in.Subject.Organizations
	} else {
		out.Organization = nil
	}

	return nil
}

func Convert_certmanager_X509Subject_To_v1alpha2_X509Subject(in *certmanager.X509Subject, out *v1alpha2.X509Subject, s conversion.Scope) error {
	return autoConvert_certmanager_X509Subject_To_v1alpha2_X509Subject(in, out, s)
}
