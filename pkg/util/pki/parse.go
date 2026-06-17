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

import (
	"crypto"
	"crypto/x509"
	stdpem "encoding/pem"

	"github.com/cert-manager/cert-manager/internal/pem"
	"github.com/cert-manager/cert-manager/pkg/util/errors"
)

// DecodePrivateKeyBytes will decode a PEM encoded private key into a crypto.Signer.
// It supports ECDSA, RSA and EdDSA private keys only. All other types will return err.
func DecodePrivateKeyBytes(keyBytes []byte) (crypto.Signer, error) {
	// decode the private key pem
	block, _, err := pem.SafeDecodePrivateKey(keyBytes)
	if err != nil {
		return nil, errors.NewInvalidData("error decoding private key PEM block: %s", err.Error())
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.NewInvalidData("error parsing pkcs#8 private key: %s", err.Error())
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.NewInvalidData("error parsing pkcs#8 private key: invalid key type")
		}
		return signer, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.NewInvalidData("error parsing ecdsa private key: %s", err.Error())
		}

		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.NewInvalidData("error parsing rsa private key: %s", err.Error())
		}

		err = key.Validate()
		if err != nil {
			return nil, errors.NewInvalidData("rsa private key failed validation: %s", err.Error())
		}
		return key, nil
	default:
		return nil, errors.NewInvalidData("unknown private key type: %s", block.Type)
	}
}

func decodeMultipleCerts(certBytes []byte, decodeFn func([]byte) (*stdpem.Block, []byte, error)) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}

	var block *stdpem.Block

	for {
		var err error

		// decode the tls certificate pem
		block, certBytes, err = decodeFn(certBytes)
		if err != nil {
			if err == pem.ErrNoPEMData {
				break
			}

			return nil, err
		}

		// parse the tls certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.NewInvalidData("error parsing X.509 certificate: %s", err.Error())
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.NewInvalidData("error decoding certificate PEM block: no valid certificates found")
	}

	return certs, nil
}

// DecodeX509CertificateChainBytes will decode a PEM encoded x509 Certificate chain with a tight
// size limit to reduce the risk of DoS attacks. If you need to decode many certificates, use
// DecodeX509CertificateSetBytes instead.
func DecodeX509CertificateChainBytes(certBytes []byte) ([]*x509.Certificate, error) {
	return decodeMultipleCerts(certBytes, pem.SafeDecodeCertificateChain)
}

// DecodeX509CertificateSetBytes will decode a concatenated set of PEM encoded x509 Certificates,
// with generous size limits to enable parsing of TLS trust bundles.
// If you need to decode a single certificate chain, use DecodeX509CertificateChainBytes instead.
func DecodeX509CertificateSetBytes(certBytes []byte) ([]*x509.Certificate, error) {
	return decodeMultipleCerts(certBytes, pem.SafeDecodeCertificateBundle)
}

// DecodeX509CertificateBytes will decode a PEM encoded x509 Certificate.
func DecodeX509CertificateBytes(certBytes []byte) (*x509.Certificate, error) {
	certs, err := DecodeX509CertificateSetBytes(certBytes)
	if err != nil {
		return nil, err
	}

	return certs[0], nil
}

// DecodeX509CertificateRequestBytes will decode a PEM encoded x509 Certificate Request.
func DecodeX509CertificateRequestBytes(csrBytes []byte) (*x509.CertificateRequest, error) {
	block, _, err := pem.SafeDecodeCSR(csrBytes)
	if err != nil {
		return nil, errors.NewInvalidData("error decoding certificate request PEM block: %s", err)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}

	return csr, nil
}
