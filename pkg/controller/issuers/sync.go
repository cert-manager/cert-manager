package issuers

import (
	"fmt"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

func sync(ctx *controller.Context, namespace, name string) error {
	acc, err := ctx.CertManagerInformerFactory.Certmanager().V1alpha1().Issuers().Lister().Issuers(namespace).Get(name)

	if err != nil {
		if k8sErrors.IsNotFound(err) {
			ctx.Logger.Printf("issuer '%s/%s' in sync queue has been deleted", namespace, name)
			return nil
		}
		return fmt.Errorf("error retreiving issuer: %s", err.Error())
	}

	i, err := issuer.IssuerFor(*ctx, acc)

	if err != nil {
		return err
	}

	return i.Setup()
}
