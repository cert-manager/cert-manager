// Package fake contains a fake implementation of the Issuer interface, useful
// for testing.
package fake

import "github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"

type Fake struct {
	SetupFunc   func() (v1alpha1.IssuerStatus, error)
	PrepareFunc func(*v1alpha1.Certificate) error
	IssueFunc   func(*v1alpha1.Certificate) ([]byte, []byte, error)
	RenewFunc   func(*v1alpha1.Certificate) ([]byte, []byte, error)
}

func (f *Fake) Setup() (v1alpha1.IssuerStatus, error) {
	return f.SetupFunc()
}

func (f *Fake) Prepare(crt *v1alpha1.Certificate) error {
	return f.PrepareFunc(crt)
}

func (f *Fake) Issue(crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	return f.IssueFunc(crt)
}

func (f *Fake) Renew(crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	return f.RenewFunc(crt)
}
