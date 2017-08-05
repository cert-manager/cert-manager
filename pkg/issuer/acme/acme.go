package acme

import (
	"context"
	"fmt"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	"github.com/munnerz/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/munnerz/cert-manager/pkg/client"
	"github.com/munnerz/cert-manager/pkg/informers/externalversions"
	"github.com/munnerz/cert-manager/pkg/issuer"
	"github.com/munnerz/cert-manager/pkg/issuer/acme/dns"
	"github.com/munnerz/cert-manager/pkg/issuer/acme/http"
)

type Acme struct {
	account *account

	client    kubernetes.Interface
	cmClient  client.Interface
	factory   informers.SharedInformerFactory
	cmFactory externalversions.SharedInformerFactory

	dnsSolver  solver
	httpSolver solver
}

func New(issuer *v1alpha1.Issuer,
	client kubernetes.Interface,
	cmClient client.Interface,
	factory informers.SharedInformerFactory,
	cmFactory externalversions.SharedInformerFactory) (issuer.Interface, error) {
	return &Acme{
		account:    newAccount(issuer, client, factory.Core().V1().Secrets().Lister()),
		client:     client,
		cmClient:   cmClient,
		factory:    factory,
		cmFactory:  cmFactory,
		dnsSolver:  dns.NewSolver(issuer, client, factory.Core().V1().Secrets().Lister()),
		httpSolver: http.NewSolver(),
	}, nil
}

type solver interface {
	Present(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error
	Wait(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error
	CleanUp(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error
}

func (a *Acme) solverFor(challengeType string) (solver, error) {
	switch challengeType {
	case "http-01":
		return a.httpSolver, nil
	case "dns-01":
		return a.dnsSolver, nil
	}
	return nil, fmt.Errorf("no solver implemented")
}

func init() {
	issuer.SharedFactory().Register(issuer.IssuerACME, New)
}
