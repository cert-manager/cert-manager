/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package issuer

import (
	"fmt"
	"sync"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
)

// IssuerConstructor constructs an issuer given an Issuer resource and a Context.
// An error will be returned if the appropriate issuer is not registered.
type IssuerConstructor func(*controller.Context, v1.GenericIssuer) (Interface, error)

var (
	constructors     = make(map[string]IssuerConstructor)
	constructorsLock sync.RWMutex
)

// RegisterIssuer will register an issuer constructor so it can be used within the
// application. 'name' should be unique, and should be used to identify this
// issuer.
// TODO: move this method to be on Factory, and invent a way to obtain a
// SharedFactory. This will make testing easier.
func RegisterIssuer(name string, c IssuerConstructor) {
	constructorsLock.Lock()
	defer constructorsLock.Unlock()
	constructors[name] = c
}

// Factory is an interface that can be used to obtain Issuer implementations.
// It determines which issuer implementation to use by introspecting the
// given Issuer resource.
type Factory interface {
	IssuerFor(v1.GenericIssuer) (Interface, error)
}

// factory is the default Factory implementation
type factory struct {
	ctx *controller.Context
}

// NewFactory returns a new issuer factory with the given issuer context.
// The context will be injected into each Issuer upon creation.
func NewFactory(ctx *controller.Context) Factory {
	return &factory{ctx: ctx}
}

// IssuerFor will return an Issuer interface for the given Issuer. If the
// requested Issuer is not registered, an error will be returned.
// A new instance of the Issuer will be returned for each call to IssuerFor,
// however this is an inexpensive operation and so, Issuers should not need
// to be cached and reused.
func (f *factory) IssuerFor(issuer v1.GenericIssuer) (Interface, error) {
	issuerType, err := apiutil.NameForIssuer(issuer)
	if err != nil {
		return nil, fmt.Errorf("could not get issuer type: %s", err.Error())
	}

	constructorsLock.RLock()
	defer constructorsLock.RUnlock()
	if constructor, ok := constructors[issuerType]; ok {
		return constructor(f.ctx, issuer)
	}

	return nil, fmt.Errorf("issuer '%s' not registered", issuerType)
}
