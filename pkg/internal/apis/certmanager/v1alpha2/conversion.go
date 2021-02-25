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

package v1alpha2

import (
	"k8s.io/apimachinery/pkg/conversion"

	"github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/cert-manager/cert-manager/pkg/internal/apis/certmanager"
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

	if in.KeyAlgorithm != "" || in.KeyEncoding != "" || in.KeySize != 0 {
		if out.PrivateKey == nil {
			out.PrivateKey = &certmanager.CertificatePrivateKey{}
		}

		switch in.KeyAlgorithm {
		case v1alpha2.ECDSAKeyAlgorithm:
			out.PrivateKey.Algorithm = certmanager.ECDSAKeyAlgorithm
		case v1alpha2.RSAKeyAlgorithm:
			out.PrivateKey.Algorithm = certmanager.RSAKeyAlgorithm
		default:
			out.PrivateKey.Algorithm = certmanager.PrivateKeyAlgorithm(in.KeyAlgorithm)
		}

		switch in.KeyEncoding {
		case v1alpha2.PKCS1:
			out.PrivateKey.Encoding = certmanager.PKCS1
		case v1alpha2.PKCS8:
			out.PrivateKey.Encoding = certmanager.PKCS8
		default:
			out.PrivateKey.Encoding = certmanager.PrivateKeyEncoding(in.KeyEncoding)
		}

		out.PrivateKey.Size = in.KeySize
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

	if in.PrivateKey != nil {
		switch in.PrivateKey.Algorithm {
		case certmanager.ECDSAKeyAlgorithm:
			out.KeyAlgorithm = v1alpha2.ECDSAKeyAlgorithm
		case certmanager.RSAKeyAlgorithm:
			out.KeyAlgorithm = v1alpha2.RSAKeyAlgorithm
		default:
			out.KeyAlgorithm = v1alpha2.KeyAlgorithm(in.PrivateKey.Algorithm)
		}

		switch in.PrivateKey.Encoding {
		case certmanager.PKCS1:
			out.KeyEncoding = v1alpha2.PKCS1
		case certmanager.PKCS8:
			out.KeyEncoding = v1alpha2.PKCS8
		default:
			out.KeyEncoding = v1alpha2.KeyEncoding(in.PrivateKey.Encoding)
		}

		out.KeySize = in.PrivateKey.Size
	}

	return nil
}

func Convert_certmanager_X509Subject_To_v1alpha2_X509Subject(in *certmanager.X509Subject, out *v1alpha2.X509Subject, s conversion.Scope) error {
	return autoConvert_certmanager_X509Subject_To_v1alpha2_X509Subject(in, out, s)
}

func Convert_certmanager_CertificatePrivateKey_To_v1alpha2_CertificatePrivateKey(in *certmanager.CertificatePrivateKey, out *v1alpha2.CertificatePrivateKey, s conversion.Scope) error {
	return autoConvert_certmanager_CertificatePrivateKey_To_v1alpha2_CertificatePrivateKey(in, out, s)
}

func Convert_v1alpha2_CertificateRequestSpec_To_certmanager_CertificateRequestSpec(in *v1alpha2.CertificateRequestSpec, out *certmanager.CertificateRequestSpec, s conversion.Scope) error {
	if err := autoConvert_v1alpha2_CertificateRequestSpec_To_certmanager_CertificateRequestSpec(in, out, s); err != nil {
		return err
	}

	out.Request = in.CSRPEM
	return nil
}

func Convert_certmanager_CertificateRequestSpec_To_v1alpha2_CertificateRequestSpec(in *certmanager.CertificateRequestSpec, out *v1alpha2.CertificateRequestSpec, s conversion.Scope) error {
	if err := autoConvert_certmanager_CertificateRequestSpec_To_v1alpha2_CertificateRequestSpec(in, out, s); err != nil {
		return err
	}

	out.CSRPEM = in.Request
	return nil
}
