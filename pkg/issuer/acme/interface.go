package acme

import (
	"fmt"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
)

type solver interface {
	Present(ctx controller.Context, crt *v1alpha1.Certificate, domain, token, key string) error
	Cleanup(ctx controller.Context, crt *v1alpha1.Certificate, domain, token string) error
}

func solverFor(challengeType string) (solver, error) {
	return nil, fmt.Errorf("no solver implemented")
}
