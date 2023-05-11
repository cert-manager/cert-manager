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

package pki

import cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

// staticTemporarySerialNumber is a fixed serial number we use for temporary certificates
const staticTemporarySerialNumber = "1234567890"

// GenerateLocallySignedTemporaryCertificate signs a temporary certificate for
// the given certificate resource using a one-use temporary CA that is then
// discarded afterwards.
// This is to mitigate a potential attack against x509 certificates that use a
// predictable serial number and weak MD5 hashing algorithms.
// In practice, this shouldn't really be a concern anyway.
func GenerateLocallySignedTemporaryCertificate(crt *cmapi.Certificate, pkData []byte) ([]byte, error) {
	// generate a throwaway self-signed root CA
	caPk, err := GenerateECPrivateKey(ECCurve521)
	if err != nil {
		return nil, err
	}
	caCertTemplate, err := CertificateTemplateFromCertificate(&cmapi.Certificate{
		Spec: cmapi.CertificateSpec{
			CommonName: "cert-manager.local",
			IsCA:       true,
		},
	})
	if err != nil {
		return nil, err
	}
	_, caCert, err := SignCertificate(caCertTemplate, caCertTemplate, caPk.Public(), caPk)
	if err != nil {
		return nil, err
	}

	// sign a temporary certificate using the root CA
	template, err := CertificateTemplateFromCertificate(crt)
	if err != nil {
		return nil, err
	}
	template.Subject.SerialNumber = staticTemporarySerialNumber

	signeeKey, err := DecodePrivateKeyBytes(pkData)
	if err != nil {
		return nil, err
	}

	b, _, err := SignCertificate(template, caCert, signeeKey.Public(), caPk)
	if err != nil {
		return nil, err
	}

	return b, nil
}
