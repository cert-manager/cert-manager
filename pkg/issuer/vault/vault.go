package vault

import (
	corelisters "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

type Vault struct {
	*controller.Context
	issuer v1alpha1.GenericIssuer

	secretsLister corelisters.SecretLister

	// Namespace in which to read resources related to this Issuer from.
	// For Issuers, this will be the namespace of the Issuer.
	// For ClusterIssuers, this will be the cluster resource namespace.
	resourceNamespace string
}

func NewVault(ctx *controller.Context, issuer v1alpha1.GenericIssuer) (issuer.Interface, error) {
	secretsLister := ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister()

	return &Vault{
		Context:           ctx,
		issuer:            issuer,
		secretsLister:     secretsLister,
		resourceNamespace: ctx.IssuerOptions.ResourceNamespace(issuer),
	}, nil
}

// Register this Issuer with the issuer factory
func init() {
	controller.RegisterIssuer(controller.IssuerVault, NewVault)
}
