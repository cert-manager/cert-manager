package issuer

import (
	"fmt"
	"sync"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/client"
	cminformers "github.com/jetstack-experimental/cert-manager/pkg/informers"
	"github.com/jetstack-experimental/cert-manager/pkg/log"
)

type Factory struct {
	constructors     map[string]Constructor
	constructorsLock sync.RWMutex

	client    kubernetes.Interface
	cmClient  client.Interface
	factory   informers.SharedInformerFactory
	cmFactory cminformers.SharedInformerFactory
}

func (f *Factory) Setup(client kubernetes.Interface,
	cmClient client.Interface,
	factory informers.SharedInformerFactory,
	cmFactory cminformers.SharedInformerFactory) {
	f.client = client
	f.cmClient = cmClient
	f.factory = factory
	f.cmFactory = cmFactory
}

func (f *Factory) IssuerFor(issuer *v1alpha1.Issuer) (Interface, error) {
	issuerType, err := nameForIssuer(issuer)
	if err != nil {
		return nil, fmt.Errorf("could not get issuer type: %s", err.Error())
	}

	f.constructorsLock.RLock()
	defer f.constructorsLock.RUnlock()
	if constructor, ok := f.constructors[issuerType]; ok {
		return constructor(issuer, f.client, f.cmClient, f.factory, f.cmFactory)
	}
	return nil, fmt.Errorf("issuer '%s' not registered", issuerType)
}

// Register will register an issuer constructor so it can be used within the
// application. 'name' should be unique, and should be used to identify this
// issuer.
func (f *Factory) Register(name string, c Constructor) {
	f.constructorsLock.Lock()
	defer f.constructorsLock.Unlock()
	log.Printf("registered issuer '%s'", name)
	f.constructors[name] = c
}
