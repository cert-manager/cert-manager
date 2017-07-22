package issuer

import (
	"fmt"

	"github.com/munnerz/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/munnerz/cert-manager/pkg/controller"
	"github.com/munnerz/cert-manager/pkg/issuer/acme"
)

type Interface interface {
	// Setup initialises the issuer. This may include registering accounts with
	// a service, creating a CA and storing it somewhere, or verifying
	// credentials and authorization with a remote server.
	Setup() error
	// Prepare
	Prepare(*v1alpha1.Certificate) error
	// Issue attempts to issue a certificate as described by the certificate
	// resource given
	Issue(*v1alpha1.Certificate) ([]byte, []byte, error)
	// Renew attempts to renew the certificate describe by the certificate
	// resource given. If no certificate exists, an error is returned.
	Renew(*v1alpha1.Certificate) ([]byte, []byte, error)
}

func IssuerFor(ctx controller.Context, issuer *v1alpha1.Issuer) (Interface, error) {
	switch {
	case issuer.Spec.ACME != nil:
		return acme.New(&ctx, issuer)
	}
	return nil, fmt.Errorf("issuer '%s' does not have an issuer specification", issuer.Name)
}
