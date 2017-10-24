package issuer

import (
	"context"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

type Interface interface {
	// Setup initialises the issuer. This may include registering accounts with
	// a service, creating a CA and storing it somewhere, or verifying
	// credentials and authorization with a remote server.
	Setup(ctx context.Context) error
	// Prepare
	Prepare(context.Context, *v1alpha1.Certificate) error
	// Issue attempts to issue a certificate as described by the certificate
	// resource given
	Issue(context.Context, *v1alpha1.Certificate) ([]byte, []byte, error)
	// Renew attempts to renew the certificate describe by the certificate
	// resource given. If no certificate exists, an error is returned.
	Renew(context.Context, *v1alpha1.Certificate) ([]byte, []byte, error)
}
