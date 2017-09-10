package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
)

func GenerateCSR(domains []string) *x509.CertificateRequest {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domains[0],
		},
		DNSNames: domains,
	}
	return &template
}
