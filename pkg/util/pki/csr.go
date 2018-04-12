package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util"
)

func CommonNameForCertificate(crt *v1alpha1.Certificate) string {
	if crt.Spec.CommonName != "" {
		return crt.Spec.CommonName
	}
	if len(crt.Spec.DNSNames) == 0 {
		return ""
	}
	return crt.Spec.DNSNames[0]
}

func DNSNamesForCertificate(crt *v1alpha1.Certificate) []string {
	if len(crt.Spec.DNSNames) == 0 {
		if crt.Spec.CommonName == "" {
			return []string{}
		}
		return []string{crt.Spec.CommonName}
	}
	if crt.Spec.CommonName != "" {
		return util.RemoveDuplicates(append([]string{crt.Spec.CommonName}, crt.Spec.DNSNames...))
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
