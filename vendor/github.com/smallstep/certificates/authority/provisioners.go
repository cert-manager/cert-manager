package authority

import (
	"crypto/x509"
	"net/http"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
)

// GetEncryptedKey returns the JWE key corresponding to the given kid argument.
func (a *Authority) GetEncryptedKey(kid string) (string, error) {
	key, ok := a.provisioners.LoadEncryptedKey(kid)
	if !ok {
		return "", &apiError{errors.Errorf("encrypted key with kid %s was not found", kid),
			http.StatusNotFound, context{}}
	}
	return key, nil
}

// GetProvisioners returns a map listing each provisioner and the JWK Key Set
// with their public keys.
func (a *Authority) GetProvisioners(cursor string, limit int) (provisioner.List, string, error) {
	provisioners, nextCursor := a.provisioners.Find(cursor, limit)
	return provisioners, nextCursor, nil
}

// LoadProvisionerByCertificate returns an interface to the provisioner that
// provisioned the certificate.
func (a *Authority) LoadProvisionerByCertificate(crt *x509.Certificate) (provisioner.Interface, error) {
	p, ok := a.provisioners.LoadByCertificate(crt)
	if !ok {
		return nil, &apiError{errors.Errorf("provisioner not found"),
			http.StatusNotFound, context{}}
	}
	return p, nil
}
