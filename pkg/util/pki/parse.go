/*
Copyright 2018 The Jetstack cert-manager contributors.

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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/jetstack/cert-manager/pkg/util/errors"
)

func DecodePrivateKeyBytes(keyBytes []byte) (crypto.Signer, error) {
	// decode the private key pem
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.NewInvalidData("error decoding private key PEM block")
	}

	switch block.Type {
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

func DecodePKCS1PrivateKeyBytes(keyBytes []byte) (*rsa.PrivateKey, error) {
	// decode the private key pem
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.NewInvalidData("error decoding private key PEM block")
	}
	// parse the private key
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.NewInvalidData("error parsing private key: %s", err.Error())
	}
	// validate the private key
	if err = key.Validate(); err != nil {
		return nil, errors.NewInvalidData("private key failed validation: %s", err.Error())
	}
	return key, nil
}

func DecodeX509CertificateBytes(certBytes []byte) (*x509.Certificate, error) {
	// decode the tls certificate pem
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, errors.NewInvalidData("error decoding cert PEM block")
	}
	// parse the tls certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.NewInvalidData("error parsing TLS certificate: %s", err.Error())
	}

	return cert, nil
}

func DecodeDERCertificateBytes(derBytes []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(derBytes)
}
