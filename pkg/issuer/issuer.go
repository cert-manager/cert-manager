package issuer

import "github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"

type Interface interface {
	// Setup initialises the issuer. This may include registering accounts with
	// a service, creating a CA and storing it somewhere, or verifying
	// credentials and authorization with a remote server.
	Setup() (v1alpha1.IssuerStatus, error)
	// Prepare
	Prepare(*v1alpha1.Certificate) (v1alpha1.CertificateStatus, error)
	// Issue attempts to issue a certificate as described by the certificate
	// resource given
	Issue(*v1alpha1.Certificate) (v1alpha1.CertificateStatus, []byte, []byte, error)
	// Renew attempts to renew the certificate describe by the certificate
	// resource given. If no certificate exists, an error is returned.
	Renew(*v1alpha1.Certificate) (v1alpha1.CertificateStatus, []byte, []byte, error)
}
