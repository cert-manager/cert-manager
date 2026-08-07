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
	"maps"
	"sync"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
)

// IssuerConstructor constructs an issuer given an Issuer resource and a Context.
// An error will be returned if the appropriate issuer is not registered.
type IssuerConstructor func(*controller.Context) (Interface, error)

var (
	// sharedFactory is a singleton used for global registration via the
	// package-level RegisterIssuer function and for callers that explicitly
	// want to interact with the shared registry.
	sharedFactory     *factory
	sharedFactoryInit sync.Once
)

// RegisterIssuer registers an issuer constructor on this factory instance.
// 'name' should be unique, and should be used to identify this issuer.
func (f *factory) RegisterIssuer(name string, c IssuerConstructor) {
	f.constructorsLock.Lock()
	defer f.constructorsLock.Unlock()
	f.constructors[name] = c
}

// RegisterIssuer registers an issuer constructor on the shared factory.
// This preserves the existing package-level API used by issuer packages
// during init().
func RegisterIssuer(name string, c IssuerConstructor) {
	SharedFactory().RegisterIssuer(name, c)
}

// Factory is an interface that can be used to obtain Issuer implementations.
// It determines which issuer implementation to use by introspecting the
// given Issuer resource.
type Factory interface {
	IssuerFor(v1.GenericIssuer) (Interface, error)
	RegisterIssuer(name string, c IssuerConstructor)
}

// factory is the default Factory implementation
type factory struct {
	constructors     map[string]IssuerConstructor
	constructorsLock sync.RWMutex

	ctx *controller.Context
}

// NewFactory returns a new issuer factory with the given issuer context.
// The context will be injected into each Issuer upon creation.
// The factory is initialized with a snapshot of the shared registry at creation time.
// Issuers registered to the shared registry after this factory is created will not be
// visible to this factory instance. Use RegisterIssuer on the returned factory to add
// instance-specific issuer registrations, or use SharedFactory() for dynamic registration.
func NewFactory(ctx *controller.Context) Factory {
	// copy the constructors registered on the shared factory so that issuers
	// registered during init() are visible by default, while allowing tests
	// to isolate registries per factory instance.
	sf := getOrInitSharedFactory()
	sf.constructorsLock.RLock()
	defer sf.constructorsLock.RUnlock()
	ctors := make(map[string]IssuerConstructor, len(sf.constructors))
	maps.Copy(ctors, sf.constructors)
	return &factory{
		constructors: ctors,
		ctx:          ctx,
	}
}

// NewFactoryWithConstructors returns a factory that uses the provided
// constructors map. Intended for tests to create fully isolated registries.
func NewFactoryWithConstructors(ctx *controller.Context, ctors map[string]IssuerConstructor) Factory {
	constructors := make(map[string]IssuerConstructor, len(ctors))
	maps.Copy(constructors, ctors)
	return &factory{
		constructors: constructors,
		ctx:          ctx,
	}
}

// SharedFactory returns a singleton Factory backed by a shared registry.
// Useful for package-level registration in init() functions and for callers
// that need a process-wide registry.
func SharedFactory() Factory {
	return getOrInitSharedFactory()
}

func getOrInitSharedFactory() *factory {
	sharedFactoryInit.Do(func() {
		sharedFactory = &factory{constructors: make(map[string]IssuerConstructor)}
	})
	return sharedFactory
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

	f.constructorsLock.RLock()
	defer f.constructorsLock.RUnlock()
	if constructor, ok := f.constructors[issuerType]; ok {
		return constructor(f.ctx)
	}

	return nil, fmt.Errorf("issuer '%s' not registered", issuerType)
}
