package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
)

func GenerateCSR(commonName string, altNames ...string) *x509.CertificateRequest {
	if commonName == "" && len(altNames) > 0 {
		commonName = altNames[0]
	}
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames: altNames,
	}
	return &template
}
