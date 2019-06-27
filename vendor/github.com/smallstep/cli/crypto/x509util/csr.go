package x509util

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// LoadCSRFromBytes loads a CSR given the ASN.1 DER format.
func LoadCSRFromBytes(der []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(der)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing CSR")
	}
	return ParseCertificateRequest(block.Bytes)
}
