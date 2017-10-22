package pki

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/jetstack/cert-manager/pkg/util/errors"
)

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
