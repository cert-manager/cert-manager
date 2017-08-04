package acme

import (
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	"github.com/munnerz/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/munnerz/cert-manager/pkg/client"
	"github.com/munnerz/cert-manager/pkg/informers/externalversions"
	"github.com/munnerz/cert-manager/pkg/issuer"
)

type Acme struct {
	account *account

	client    kubernetes.Interface
	cmClient  client.Interface
	factory   informers.SharedInformerFactory
	cmFactory externalversions.SharedInformerFactory
}

func New(issuer *v1alpha1.Issuer,
	client kubernetes.Interface,
	cmClient client.Interface,
	factory informers.SharedInformerFactory,
	cmFactory externalversions.SharedInformerFactory) (issuer.Interface, error) {
	return &Acme{
		account:   newAccount(issuer, client, factory.Core().V1().Secrets().Lister()),
		client:    client,
		cmClient:  cmClient,
		factory:   factory,
		cmFactory: cmFactory,
	}, nil
}

func (a *Acme) Renew(crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	return a.obtainCertificate(crt)
}

func init() {
	issuer.SharedFactory().Register(issuer.IssuerACME, New)
}
