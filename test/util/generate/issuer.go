package generate

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

type IssuerConfig struct {
	Name, Namespace string
	HTTP01          *v1alpha1.ACMEIssuerHTTP01Config
	DNS01           *v1alpha1.ACMEIssuerDNS01Config
}

func Issuer(cfg IssuerConfig) *v1alpha1.Issuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cfg.Name,
			Namespace: cfg.Namespace,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				ACME: &v1alpha1.ACMEIssuer{
					HTTP01: cfg.HTTP01,
					DNS01:  cfg.DNS01,
				},
			},
		},
	}
}
