package issuer

import (
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	"github.com/munnerz/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/munnerz/cert-manager/pkg/client"
	"github.com/munnerz/cert-manager/pkg/informers/externalversions"
)

var sharedFactory = &Factory{
	constructors: make(map[string]Constructor),
}

func SharedFactory() *Factory {
	return sharedFactory
}

type Constructor func(issuer *v1alpha1.Issuer,
	client kubernetes.Interface,
	cmClient client.Interface,
	factory informers.SharedInformerFactory,
	cmFactory externalversions.SharedInformerFactory) (Interface, error)

type Interface interface {
	// Setup initialises the issuer. This may include registering accounts with
	// a service, creating a CA and storing it somewhere, or verifying
	// credentials and authorization with a remote server.
	Setup() error
	// Prepare
	Prepare(*v1alpha1.Certificate) error
	// Issue attempts to issue a certificate as described by the certificate
	// resource given
	Issue(*v1alpha1.Certificate) ([]byte, []byte, error)
	// Renew attempts to renew the certificate describe by the certificate
	// resource given. If no certificate exists, an error is returned.
	Renew(*v1alpha1.Certificate) ([]byte, []byte, error)
}
