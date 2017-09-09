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

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/client/clientset"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer/acme/dns"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer/acme/http"
)

type Acme struct {
	issuer *v1alpha1.Issuer

	client   kubernetes.Interface
	cmClient clientset.Interface

	secretsLister corelisters.SecretLister

	dnsSolver  solver
	httpSolver solver
}

func New(issuer *v1alpha1.Issuer,
	client kubernetes.Interface,
	cmClient clientset.Interface,
	secretsInformer cache.SharedIndexInformer) (issuer.Interface, error) {
	if issuer.Spec.ACME == nil {
		return nil, fmt.Errorf("acme config may not be empty")
	}

	secretsLister := corelisters.NewSecretLister(secretsInformer.GetIndexer())
	return &Acme{
		issuer:        issuer,
		client:        client,
		cmClient:      cmClient,
		secretsLister: secretsLister,
		dnsSolver:     dns.NewSolver(issuer, client, secretsLister),
		httpSolver:    http.NewSolver(issuer, client, secretsLister),
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
	issuer.Register(issuer.IssuerACME, func(i *v1alpha1.Issuer, ctx *issuer.Context) (issuer.Interface, error) {
		return New(
			i,
			ctx.Client,
			ctx.CMClient,
			ctx.SharedInformerFactory.InformerFor(
				ctx.Namespace,
				metav1.GroupVersionKind{Version: "v1", Kind: "Secret"},
				coreinformers.NewSecretInformer(ctx.Client, ctx.Namespace, time.Second*30, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})),
		)
	})
}
