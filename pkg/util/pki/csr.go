package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// The provided Certificate *must* specify either a DNS name or a
// CommonName else this function will panic.
func CommonNameForCertificate(crt *v1alpha1.Certificate) string {
	if crt.Spec.CommonName == "" {
		return crt.Spec.DNSNames[0]
	}
	return crt.Spec.CommonName
}

// The provided Certificate *must* specify either a DNS name or a
// CommonName else this function will panic.
func DNSNamesForCertificate(crt *v1alpha1.Certificate) []string {
	if len(crt.Spec.DNSNames) == 0 {
		return []string{crt.Spec.CommonName}
	}
	if crt.Spec.CommonName != "" {
		return append([]string{crt.Spec.CommonName}, crt.Spec.DNSNames...)
	}
	return crt.Spec.DNSNames
}

func GenerateCSR(commonName string, altNames ...string) *x509.CertificateRequest {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames: altNames,
	}
	return &template
}
