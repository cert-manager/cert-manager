package issuer

import (
	"fmt"

	"k8s.io/client-go/tools/cache"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
)

const (
	IssuerACME string = "acme"
	IssuerCA   string = "ca"
)

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
