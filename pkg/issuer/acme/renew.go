package acme

import "github.com/munnerz/cert-manager/pkg/apis/certmanager/v1alpha1"

func (a *Acme) Renew(crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	return a.obtainCertificate(crt)
}
