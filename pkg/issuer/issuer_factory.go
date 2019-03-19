/*
Copyright 2019 The Jetstack cert-manager contributors.

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

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
)

// issuerConstructor constructs an issuer given an Issuer resource and a Context.
// An error will be returned if the appropriate issuer is not registered.
type IssuerConstructor func(*controller.Context, v1alpha1.GenericIssuer) (Interface, error)

var (
	constructors     = make(map[string]IssuerConstructor)
	constructorsLock sync.RWMutex
)

// Register will register an issuer constructor so it can be used within the
// application. 'name' should be unique, and should be used to identify this
// issuer.
// TODO: move this method to be on Factory, and invent a way to obtain a
// SharedFactory. This will make testing easier.
func RegisterIssuer(name string, c IssuerConstructor) {
	constructorsLock.Lock()
	defer constructorsLock.Unlock()
	constructors[name] = c
}

// IssuerFactory is an interface that can be used to obtain Issuer implementations.
// It determines which issuer implementation to use by introspecting the
// given Issuer resource.
type IssuerFactory interface {
	IssuerFor(v1alpha1.GenericIssuer) (Interface, error)
}

type fakeFactory struct {
	ctx         *controller.Context
	constructor IssuerConstructor
}

func NewFakeFactory(ctx *controller.Context, constructor IssuerConstructor) IssuerFactory {
	return &fakeFactory{ctx, constructor}
}

func (f *fakeFactory) IssuerFor(iss v1alpha1.GenericIssuer) (Interface, error) {
	return f.constructor(f.ctx, iss)
}

// factory is the default Factory implementation
type factory struct {
	ctx *controller.Context
}

// NewIssuerFactory returns a new issuer factory with the given issuer context.
// The context will be injected into each Issuer upon creation.
func NewIssuerFactory(ctx *controller.Context) IssuerFactory {
	return &factory{ctx: ctx}
}

// IssuerFor will return an Issuer interface for the given Issuer. If the
// requested Issuer is not registered, an error will be returned.
// A new instance of the Issuer will be returned for each call to IssuerFor,
// however this is an inexpensive operation and so, Issuers should not need
// to be cached and reused.
func (f *factory) IssuerFor(issuer v1alpha1.GenericIssuer) (Interface, error) {
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
