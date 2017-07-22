package acme

import (
	"fmt"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	http01 "github.com/jetstack/cert-manager/pkg/issuer/acme/http"
)

type solver interface {
	Present(ctx controller.Context, crt *v1alpha1.Certificate, domain, token, key string) error
	Cleanup(ctx controller.Context, crt *v1alpha1.Certificate, domain, token string) error
}

var httpSolver = http01.NewSolver()

func solverFor(challengeType string) (solver, error) {
	switch challengeType {
	case "http-01":
		return httpSolver, nil
	}
	return nil, fmt.Errorf("no solver implemented")
}
