package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util"
)

// The provided Certificate *must* specify either a DNS name or a
// CommonName else this function will panic.
func CommonNameForCertificate(crt *v1alpha1.Certificate) (string, error) {
	if crt.Spec.CommonName != "" {
		return crt.Spec.CommonName, nil
	}
	if len(crt.Spec.DNSNames) == 0 {
		return "", fmt.Errorf("certificate must specify at least one of dnsNames or commonName")
	}
	return crt.Spec.DNSNames[0], nil
}

// The provided Certificate *must* specify either a DNS name or a
// CommonName else this function will panic.
func DNSNamesForCertificate(crt *v1alpha1.Certificate) ([]string, error) {
	if len(crt.Spec.DNSNames) == 0 {
		if crt.Spec.CommonName == "" {
			return nil, fmt.Errorf("certificate must specify at least one of dnsNames or commonName")
		}
		return []string{crt.Spec.CommonName}, nil
	}
	if crt.Spec.CommonName != "" {
		return util.RemoveDuplicates(append([]string{crt.Spec.CommonName}, crt.Spec.DNSNames...)), nil
	}
	return crt.Spec.DNSNames, nil
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
