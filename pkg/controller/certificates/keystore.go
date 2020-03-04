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

// This file defines methods used for PKCS#12 support.
// This is an experimental feature and the contents of this file are intended
// to be absorbed into a more fully fledged implementing ahead of the v0.15
// release.
// This should hopefully not exist by the next time you come to read this :)

package certificates

import (
	"crypto/rand"
	"crypto/x509"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	// pkcs12SecretKey is the name of the data entry in the Secret resource
	// used to store the p12 file.
	pkcs12SecretKey = "keystore.p12"
)

// encodePKCS12Keystore will encode a PKCS12 keystore using the password provided.
// The key, certificate and CA data must be provided in PKCS1 or PKCS8 PEM format.
// If the certificate data contains multiple certificates, the first will be used
// as the keystores 'certificate' and the remaining certificates will be prepended
// to the list of CAs in the resulting keystore.
func encodePKCS12Keystore(password string, rawKey []byte, certPem []byte, caPem []byte) ([]byte, error) {
	key, err := pki.DecodePrivateKeyBytes(rawKey)
	if err != nil {
		return nil, err
	}
	certs, err := pki.DecodeX509CertificateChainBytes(certPem)
	if err != nil {
		return nil, err
	}
	var cas []*x509.Certificate
	if len(caPem) > 0 {
		cas, err = pki.DecodeX509CertificateChainBytes(caPem)
		if err != nil {
			return nil, err
		}
		// prepend the certificate chain to the list of certificates as the PKCS12
		// library only allows setting a single certificate.
		if len(certs) > 1 {
			cas = append(certs[1:], cas...)
		}
	}
	keystoreData, err := pkcs12.Encode(rand.Reader, key, certs[0], cas, password)
	if err != nil {
		return nil, err
	}
	return keystoreData, nil
}
