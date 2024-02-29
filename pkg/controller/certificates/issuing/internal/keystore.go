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

// This file defines methods used for PKCS#12 support.
// This is an experimental feature and the contents of this file are intended
// to be absorbed into a more fully fledged implementing ahead of the v0.15
// release.
// This should hopefully not exist by the next time you come to read this :)

package internal

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"time"

	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// encodePKCS12Keystore will encode a PKCS12 keystore using the password provided.
// The key, certificate and CA data must be provided in PKCS1 or PKCS8 PEM format.
// If the certificate data contains multiple certificates, the first will be used
// as the keystores 'certificate' and the remaining certificates will be prepended
// to the list of CAs in the resulting keystore.
func encodePKCS12Keystore(profile cmapi.PKCS12Profile, password string, rawKey []byte, certPem []byte, caPem []byte) ([]byte, error) {
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
		cas, err = pki.DecodeX509CertificateSetBytes(caPem)
		if err != nil {
			return nil, err
		}
	}
	// prepend the certificate chain to the list of certificates as the PKCS12
	// library only allows setting a single certificate.
	if len(certs) > 1 {
		cas = append(certs[1:], cas...)
	}

	switch profile {
	case cmapi.Modern2023PKCS12Profile:
		return pkcs12.Modern2023.Encode(key, certs[0], cas, password)
	case cmapi.LegacyDESPKCS12Profile:
		return pkcs12.LegacyDES.Encode(key, certs[0], cas, password)
	case cmapi.LegacyRC2PKCS12Profile:
		return pkcs12.LegacyRC2.Encode(key, certs[0], cas, password)
	default:
		return pkcs12.LegacyRC2.Encode(key, certs[0], cas, password)
	}
}

func encodePKCS12Truststore(profile cmapi.PKCS12Profile, password string, caPem []byte) ([]byte, error) {
	cas, err := pki.DecodeX509CertificateSetBytes(caPem)
	if err != nil {
		return nil, err
	}

	switch profile {
	case cmapi.Modern2023PKCS12Profile:
		return pkcs12.Modern2023.EncodeTrustStore(cas, password)
	case cmapi.LegacyDESPKCS12Profile:
		return pkcs12.LegacyDES.EncodeTrustStore(cas, password)
	case cmapi.LegacyRC2PKCS12Profile:
		return pkcs12.LegacyRC2.EncodeTrustStore(cas, password)
	default:
		return pkcs12.LegacyRC2.EncodeTrustStore(cas, password)
	}
}

func encodeJKSKeystore(password []byte, keyAlias string, rawKey []byte, certPem []byte, caPem []byte) ([]byte, error) {
	// encode the private key to PKCS8
	key, err := pki.DecodePrivateKeyBytes(rawKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	// encode the certificate chain
	chain, err := pki.DecodeX509CertificateChainBytes(certPem)
	if err != nil {
		return nil, err
	}
	certs := make([]jks.Certificate, len(chain))
	for i, cert := range chain {
		certs[i] = jks.Certificate{
			Type:    "X509",
			Content: cert.Raw,
		}
	}

	ks := jks.New()
	if err = ks.SetPrivateKeyEntry(keyAlias, jks.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       keyDER,
		CertificateChain: certs,
	}, password); err != nil {
		return nil, err
	}

	// add the CA certificate, if set
	if len(caPem) > 0 {
		if err := addCAsToJKSStore(&ks, caPem); err != nil {
			return nil, err
		}
	}

	buf := &bytes.Buffer{}
	if err := ks.Store(buf, password); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeJKSTruststore(password []byte, caPem []byte) ([]byte, error) {
	ks := jks.New()
	if err := addCAsToJKSStore(&ks, caPem); err != nil {
		return nil, err
	}
	buf := &bytes.Buffer{}
	if err := ks.Store(buf, password); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func addCAsToJKSStore(ks *jks.KeyStore, caPem []byte) error {
	cas, err := pki.DecodeX509CertificateSetBytes(caPem)
	if err != nil {
		return err
	}

	creationTime := time.Now()
	for i, ca := range cas {
		alias := fmt.Sprintf("ca-%d", i)
		if i == 0 {
			alias = "ca"
		}
		if err = ks.SetTrustedCertificateEntry(alias, jks.TrustedCertificateEntry{
			CreationTime: creationTime,
			Certificate: jks.Certificate{
				Type:    "X509",
				Content: ca.Raw,
			}},
		); err != nil {
			return err
		}
	}
	return nil
}
