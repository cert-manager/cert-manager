package acme

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/client/clientset"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer/acme/dns"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer/acme/http"
)

// Acme is an issuer for an ACME server. It can be used to register and obtain
// certificates from any ACME server. It supports DNS01 and HTTP01 challenge
// mechanisms.
type Acme struct {
	issuer v1alpha1.GenericIssuer

	client   kubernetes.Interface
	cmClient clientset.Interface
	recorder record.EventRecorder

	secretsLister corelisters.SecretLister

	dnsSolver  solver
	httpSolver solver
}

// New returns a new ACME issuer interface for the given issuer.
func New(issuer v1alpha1.GenericIssuer,
	client kubernetes.Interface,
	cmClient clientset.Interface,
	recorder record.EventRecorder,
	secretsInformer cache.SharedIndexInformer) (issuer.Interface, error) {
	if issuer.GetSpec().ACME == nil {
		return nil, fmt.Errorf("acme config may not be empty")
	}

	secretsLister := corelisters.NewSecretLister(secretsInformer.GetIndexer())

	return &Acme{
		issuer:        issuer,
		client:        client,
		cmClient:      cmClient,
		recorder:      recorder,
		secretsLister: secretsLister,
		dnsSolver:     dns.NewSolver(issuer, client, secretsLister),
		httpSolver:    http.NewSolver(issuer, client, secretsLister),
	}, nil
}

// solver solves ACME challenges by presenting the given token and key in an
// appropriate way given the config in the Issuer and Certificate.
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

// Register this Issuer with the issuer factory
func init() {
	issuer.Register(issuer.IssuerACME, func(i v1alpha1.GenericIssuer, ctx *issuer.Context) (issuer.Interface, error) {

		return New(
			i,
			ctx.Client,
			ctx.CMClient,
			ctx.Recorder,
			ctx.SharedInformerFactory.InformerFor(
				ctx.Namespace,
				metav1.GroupVersionKind{Version: "v1", Kind: "Secret"},
				coreinformers.NewSecretInformer(ctx.Client, ctx.Namespace, time.Second*30, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})),
		)
	})
}
