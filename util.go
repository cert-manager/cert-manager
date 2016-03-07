package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
)

func pemExpiryDate(certPem []byte) (time.Time, error) {
	block, _ := pem.Decode([]byte(certPem))
	if block == nil {
		return time.Time{}, errors.New("Error parsing PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}

	return cert.NotAfter, nil
}
