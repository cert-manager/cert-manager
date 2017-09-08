package issuer

import (
	"fmt"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
)

type Factory interface {
	IssuerFor(*v1alpha1.Issuer) (Interface, error)
}

func NewFactory(ctx *Context) Factory {
	return &factory{ctx: ctx}
}

type factory struct {
	ctx *Context
}

func (f *factory) IssuerFor(issuer *v1alpha1.Issuer) (Interface, error) {
	issuerType, err := nameForIssuer(issuer)
	if err != nil {
		return nil, fmt.Errorf("could not get issuer type: %s", err.Error())
	}

	constructorsLock.RLock()
	defer constructorsLock.RUnlock()
	if constructor, ok := constructors[issuerType]; ok {
		return constructor(issuer, f.ctx)
	}
	return nil, fmt.Errorf("issuer '%s' not registered", issuerType)
}

// Register will register an issuer constructor so it can be used within the
// application. 'name' should be unique, and should be used to identify this
// issuer.
func Register(name string, c Constructor) {
	constructorsLock.Lock()
	defer constructorsLock.Unlock()
	constructors[name] = c
}
