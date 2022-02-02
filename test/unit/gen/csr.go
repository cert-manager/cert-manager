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

package gen

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

type CSRModifier func(*x509.CertificateRequest)

func CSR(keyAlgorithm x509.PublicKeyAlgorithm, mods ...CSRModifier) (csr []byte, sk crypto.Signer, err error) {
	var signatureAlgorithm x509.SignatureAlgorithm

	switch keyAlgorithm {
	case x509.RSA:
		sk, err = pki.GenerateRSAPrivateKey(2048)
		if err != nil {
			return nil, nil, err
		}
		signatureAlgorithm = x509.SHA256WithRSA
	case x509.ECDSA:
		sk, err = pki.GenerateECPrivateKey(pki.ECCurve256)
		if err != nil {
			return nil, nil, err
		}
		signatureAlgorithm = x509.ECDSAWithSHA256
	case x509.Ed25519:
		sk, err = pki.GenerateEd25519PrivateKey()
		if err != nil {
			return nil, nil, err
		}
		signatureAlgorithm = x509.PureEd25519
	default:
		return nil, nil, fmt.Errorf("unrecognised key algorithm: %s", err)
	}

	cr := &x509.CertificateRequest{
		Version:            3,
		SignatureAlgorithm: signatureAlgorithm,
		PublicKeyAlgorithm: keyAlgorithm,
		PublicKey:          sk.Public(),
	}
	for _, mod := range mods {
		mod(cr)
	}

	csrBytes, err := pki.EncodeCSR(cr, sk)
	if err != nil {
		return nil, nil, err
	}
	csr = pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrBytes,
	})
	return
}

func SetCSRDNSNames(dnsNames ...string) CSRModifier {
	return func(c *x509.CertificateRequest) {
		c.DNSNames = dnsNames
	}
}

func SetCSRIPAddresses(ips ...net.IP) CSRModifier {
	return func(c *x509.CertificateRequest) {
		c.IPAddresses = ips
	}
}

func SetCSRURIs(uris ...*url.URL) CSRModifier {
	return func(c *x509.CertificateRequest) {
		c.URIs = uris
	}
}

func SetCSRCommonName(commonName string) CSRModifier {
	return func(c *x509.CertificateRequest) {
		c.Subject.CommonName = commonName
	}
}

func SetCSREmails(emails []string) CSRModifier {
	return func(c *x509.CertificateRequest) {
		c.EmailAddresses = emails
	}
}
