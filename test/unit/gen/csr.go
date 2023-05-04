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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

type CSRModifier func(*x509.CertificateRequest) error

func CSR(keyAlgorithm x509.PublicKeyAlgorithm, mods ...CSRModifier) (csr []byte, sk crypto.Signer, err error) {
	switch keyAlgorithm {
	case x509.RSA:
		sk, err = pki.GenerateRSAPrivateKey(pki.MinRSAKeySize)
		if err != nil {
			return nil, nil, err
		}
	case x509.ECDSA:
		sk, err = pki.GenerateECPrivateKey(pki.ECCurve256)
		if err != nil {
			return nil, nil, err
		}
	case x509.Ed25519:
		sk, err = pki.GenerateEd25519PrivateKey()
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("unrecognised key algorithm: %s", keyAlgorithm)
	}

	csr, err = CSRWithSigner(sk, mods...)
	return
}

func CSRWithSigner(sk crypto.Signer, mods ...CSRModifier) (csr []byte, err error) {
	var keyAlgorithm x509.PublicKeyAlgorithm
	var signatureAlgorithm x509.SignatureAlgorithm

	switch pub := sk.Public().(type) {
	case *rsa.PublicKey:
		keyAlgorithm = x509.RSA
		keySize := pub.N.BitLen()
		switch {
		case keySize >= 4096:
			signatureAlgorithm = x509.SHA512WithRSA
		case keySize >= 3072:
			signatureAlgorithm = x509.SHA384WithRSA
		case keySize >= 2048:
			signatureAlgorithm = x509.SHA256WithRSA
		default:
			signatureAlgorithm = x509.SHA1WithRSA
		}
	case *ecdsa.PublicKey:
		keyAlgorithm = x509.ECDSA
		switch pub.Curve {
		case elliptic.P256():
			signatureAlgorithm = x509.ECDSAWithSHA256
		case elliptic.P384():
			signatureAlgorithm = x509.ECDSAWithSHA384
		case elliptic.P521():
			signatureAlgorithm = x509.ECDSAWithSHA512
		default:
			signatureAlgorithm = x509.ECDSAWithSHA1
		}
	case ed25519.PublicKey:
		keyAlgorithm = x509.Ed25519
		signatureAlgorithm = x509.PureEd25519
	default:
		return nil, fmt.Errorf("unrecognised public key type: %T", sk)
	}

	cr := &x509.CertificateRequest{
		Version:            0,
		SignatureAlgorithm: signatureAlgorithm,
		PublicKeyAlgorithm: keyAlgorithm,
		PublicKey:          sk.Public(),
	}
	for _, mod := range mods {
		err = mod(cr)
		if err != nil {
			return
		}
	}

	csrBytes, err := pki.EncodeCSR(cr, sk)
	if err != nil {
		return nil, err
	}
	csr = pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrBytes,
	})
	return
}

func SetCSRDNSNames(dnsNames ...string) CSRModifier {
	return func(c *x509.CertificateRequest) error {
		c.DNSNames = dnsNames
		return nil
	}
}

func SetCSRIPAddresses(ips ...net.IP) CSRModifier {
	return func(c *x509.CertificateRequest) error {
		c.IPAddresses = ips
		return nil
	}
}

func SetCSRIPAddressesFromStrings(ips ...string) CSRModifier {
	return func(c *x509.CertificateRequest) error {
		var certIPs []net.IP
		for _, ip := range ips {
			if certIP := net.ParseIP(ip); certIP == nil {
				return fmt.Errorf("invalid ip: %s", ip)
			} else {
				certIPs = append(certIPs, certIP)
			}
		}
		c.IPAddresses = certIPs
		return nil
	}
}

func SetCSRURIs(uris ...*url.URL) CSRModifier {
	return func(c *x509.CertificateRequest) error {
		c.URIs = uris
		return nil
	}
}

func SetCSRURIsFromStrings(uris ...string) CSRModifier {
	return func(c *x509.CertificateRequest) error {
		var certUris []*url.URL
		for _, uri := range uris {
			parsed, err := url.Parse(uri)
			if err != nil {
				return err
			}
			certUris = append(certUris, parsed)
		}
		c.URIs = certUris
		return nil
	}
}

func SetCSRCommonName(commonName string) CSRModifier {
	return func(c *x509.CertificateRequest) error {
		c.Subject.CommonName = commonName
		return nil
	}
}

func SetCSREmails(emails []string) CSRModifier {
	return func(c *x509.CertificateRequest) error {
		c.EmailAddresses = emails
		return nil
	}
}
