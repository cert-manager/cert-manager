package issuer

import (
	"fmt"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// Factory is an interface that can be used to obtain Issuer implementations.
// It determines which issuer implementation to use by introspecting the
// given Issuer resource.
type Factory interface {
	IssuerFor(v1alpha1.GenericIssuer) (Interface, error)
}

// NewFactory returns a new issuer factory with the given issuer context.
// The context will be injected into each Issuer upon creation.
func NewFactory(ctx *Context) Factory {
	return &factory{ctx: ctx}
}

// factory is the default Factory implementation
type factory struct {
	ctx *Context
}

// IssuerFor will return an Issuer interface for the given Issuer. If the
// requested Issuer is not registered, an error will be returned.
// A new instance of the Issuer will be returned for each call to IssuerFor,
// however this is an inexpensive operation and so, Issuers should not need
// to be cached and reused.
func (f *factory) IssuerFor(issuer v1alpha1.GenericIssuer) (Interface, error) {
	issuerType, err := NameForIssuer(issuer)
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
