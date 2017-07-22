package acme

import (
	"fmt"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func (a *Acme) Issue(crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	return nil, nil, fmt.Errorf("not implemented")
}
