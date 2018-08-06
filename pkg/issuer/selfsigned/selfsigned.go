package selfsigned

import (
	corelisters "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

// SelfSigned is an Issuer implementation the simply self-signs Certificates.
type SelfSigned struct {
	*controller.Context
	issuer v1alpha1.GenericIssuer

	secretsLister corelisters.SecretLister
}

func NewSelfSigned(ctx *controller.Context, issuer v1alpha1.GenericIssuer) (issuer.Interface, error) {
	secretsLister := ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister()

	return &SelfSigned{
		Context:       ctx,
		issuer:        issuer,
		secretsLister: secretsLister,
	}, nil
}

func init() {
	controller.RegisterIssuer(controller.IssuerSelfSigned, NewSelfSigned)
}
