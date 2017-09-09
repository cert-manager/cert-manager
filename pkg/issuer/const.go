package issuer

import (
	"fmt"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
)

const (
	// IssuerACME is the name of the ACME issuer
	IssuerACME string = "acme"
	// IssuerCA is the name of the simple issuer
	IssuerCA string = "ca"
)

// nameForIssuer determines the name of the issuer implementation given an
// Issuer resource.
func nameForIssuer(i *v1alpha1.Issuer) (string, error) {
	switch {
	case i.Spec.ACME != nil:
		return IssuerACME, nil
	}
	return "", fmt.Errorf("no issuer specified for Issuer '%s/%s'", i.Namespace, i.Name)
}

func issuerKeyFunc(i *v1alpha1.Issuer) (string, error) {
	return cache.DeletionHandlingMetaNamespaceKeyFunc(i)
}
