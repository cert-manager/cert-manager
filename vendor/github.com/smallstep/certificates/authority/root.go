package authority

import (
	"crypto/x509"
	"net/http"

	"github.com/pkg/errors"
)

// Root returns the certificate corresponding to the given SHA sum argument.
func (a *Authority) Root(sum string) (*x509.Certificate, error) {
	val, ok := a.certificates.Load(sum)
	if !ok {
		return nil, &apiError{errors.Errorf("certificate with fingerprint %s was not found", sum),
			http.StatusNotFound, context{}}
	}

	crt, ok := val.(*x509.Certificate)
	if !ok {
		return nil, &apiError{errors.Errorf("stored value is not a *x509.Certificate"),
			http.StatusInternalServerError, context{}}
	}
	return crt, nil
}

// GetRootCertificate returns the server root certificate.
func (a *Authority) GetRootCertificate() *x509.Certificate {
	return a.rootX509Certs[0]
}

// GetRootCertificates returns the server root certificates.
//
// In the Authority interface we also have a similar method, GetRoots, at the
// moment the functionality of these two methods are almost identical, but this
// method is intended to be used internally by CA HTTP server to load the roots
// that will be set in the tls.Config while GetRoots will be used by the
// Authority interface and might have extra checks in the future.
func (a *Authority) GetRootCertificates() []*x509.Certificate {
	return a.rootX509Certs
}

// GetRoots returns all the root certificates for this CA.
// This method implements the Authority interface.
func (a *Authority) GetRoots() ([]*x509.Certificate, error) {
	return a.rootX509Certs, nil
}

// GetFederation returns all the root certificates in the federation.
// This method implements the Authority interface.
func (a *Authority) GetFederation() (federation []*x509.Certificate, err error) {
	a.certificates.Range(func(k, v interface{}) bool {
		crt, ok := v.(*x509.Certificate)
		if !ok {
			federation = nil
			err = &apiError{errors.Errorf("stored value is not a *x509.Certificate"),
				http.StatusInternalServerError, context{}}
			return false
		}
		federation = append(federation, crt)
		return true
	})
	return
}
