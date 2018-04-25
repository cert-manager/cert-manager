package generate

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

type CertificateConfig struct {
	// metadata
	Name, Namespace string

	// common parameters
	IssuerName, IssuerKind string
	SecretName             string
	CommonName             string
	DNSNames               []string

	// ACME parameters
	ACMESolverConfig v1alpha1.ACMESolverConfig
	ACMEOrderURL     string
}

func Certificate(cfg CertificateConfig) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cfg.Name,
			Namespace: cfg.Namespace,
		},
		Spec: v1alpha1.CertificateSpec{
			SecretName: cfg.SecretName,
			IssuerRef: v1alpha1.ObjectReference{
				Name: cfg.IssuerName,
				Kind: cfg.IssuerKind,
			},
			CommonName: cfg.CommonName,
			DNSNames:   cfg.DNSNames,
			ACME: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.ACMECertificateDomainConfig{
					{
						Domains:          cfg.DNSNames,
						ACMESolverConfig: cfg.ACMESolverConfig,
					},
				},
			},
		},
		Status: v1alpha1.CertificateStatus{
			ACME: &v1alpha1.CertificateACMEStatus{
				Order: v1alpha1.ACMEOrderStatus{
					URL: cfg.ACMEOrderURL,
				},
			},
		},
	}
}
