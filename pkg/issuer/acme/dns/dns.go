package dns

import (
	"github.com/munnerz/cert-manager/pkg/apis/certmanager/v1alpha1"
)

type solver interface {
	Present(crt *v1alpha1.Certificate, domain, token, key string) error
	Cleanup(crt *v1alpha1.Certificate, domain, token string) error
}
