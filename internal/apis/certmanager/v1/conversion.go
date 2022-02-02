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

package v1

import (
	unsafe "unsafe"

	conversion "k8s.io/apimachinery/pkg/conversion"

	certmanager "github.com/cert-manager/cert-manager/internal/apis/certmanager"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// Convert_v1_CertificateSpec_To_certmanager_CertificateSpec
func Convert_v1_CertificateSpec_To_certmanager_CertificateSpec(in *v1.CertificateSpec, out *certmanager.CertificateSpec, s conversion.Scope) error {
	out.URISANs = *(*[]string)(unsafe.Pointer(&in.URIs))
	out.EmailSANs = *(*[]string)(unsafe.Pointer(&in.EmailAddresses))
	return autoConvert_v1_CertificateSpec_To_certmanager_CertificateSpec(in, out, s)
}

// Convert_certmanager_CertificateSpec_To_v1_CertificateSpec
func Convert_certmanager_CertificateSpec_To_v1_CertificateSpec(in *certmanager.CertificateSpec, out *v1.CertificateSpec, s conversion.Scope) error {
	out.URIs = *(*[]string)(unsafe.Pointer(&in.URISANs))
	out.EmailAddresses = *(*[]string)(unsafe.Pointer(&in.EmailSANs))
	return autoConvert_certmanager_CertificateSpec_To_v1_CertificateSpec(in, out, s)
}
