package issuer

import (
	"fmt"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

const (
	// IssuerACME is the name of the ACME issuer
	IssuerACME string = "acme"
	// IssuerCA is the name of the simple issuer
	IssuerCA string = "ca"
	// IssuerVault is the name of the Vault issuer
	IssuerVault string = "vault"
)

// nameForIssuer determines the name of the issuer implementation given an
// Issuer resource.
func nameForIssuer(i v1alpha1.GenericIssuer) (string, error) {
	switch {
	case i.GetSpec().ACME != nil:
		return IssuerACME, nil
	case i.GetSpec().CA != nil:
		return IssuerCA, nil
	case i.GetSpec().Vault != nil:
		return IssuerVault, nil
	}
	return "", fmt.Errorf("no issuer specified for Issuer '%s/%s'", i.GetObjectMeta().Namespace, i.GetObjectMeta().Name)
}
