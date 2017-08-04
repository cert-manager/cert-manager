package issuers

import (
	"github.com/munnerz/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/munnerz/cert-manager/pkg/issuer"
)

func (c *controller) sync(iss *v1alpha1.Issuer) error {
	i, err := issuer.SharedFactory().IssuerFor(iss)

	if err != nil {
		return err
	}

	return i.Setup()
}
