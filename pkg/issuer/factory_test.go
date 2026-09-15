/*
Copyright 2025 The cert-manager Authors.

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
	"context"
	"sync"
	"testing"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
)

type dummyIssuer struct{}

func (d dummyIssuer) Setup(ctx context.Context, _ v1.GenericIssuer) error { return nil }

func dummyCtor(_ *controller.Context) (Interface, error) { return dummyIssuer{}, nil }

func newSelfSignedIssuer() *v1.Issuer {
	return &v1.Issuer{
		Spec: v1.IssuerSpec{IssuerConfig: v1.IssuerConfig{SelfSigned: &v1.SelfSignedIssuer{}}},
	}
}

func Test_NewFactory_SeesSharedRegistration(t *testing.T) {
	// NOTE: This test manipulates the package-level sharedFactory variable and
	// MUST NOT be run in parallel with other tests. Running this test concurrently
	// with other tests that use the shared factory would cause race conditions.
	// Go tests are sequential by default unless t.Parallel() is called.

	// Save and restore the shared factory state to avoid cross-test pollution.
	oldShared := sharedFactory
	oldInit := sharedFactoryInit
	t.Cleanup(func() {
		sharedFactory = oldShared
		sharedFactoryInit = oldInit
	})

	// Reset both sharedFactory and sharedFactoryInit to ensure consistent state.
	// This prevents sync.Once from blocking reinitialization.
	sharedFactory = &factory{constructors: make(map[string]IssuerConstructor)}
	sharedFactoryInit = sync.Once{}
	RegisterIssuer(apiutil.IssuerSelfSigned, dummyCtor)

	f := NewFactory(&controller.Context{})
	if _, err := f.IssuerFor(newSelfSignedIssuer()); err != nil {
		t.Fatalf("expected shared registration to be visible to NewFactory, got error: %v", err)
	}
}

func Test_FactoryLocalRegistration_Isolated(t *testing.T) {
	// NOTE: This test manipulates the package-level sharedFactory variable and
	// MUST NOT be run in parallel with other tests. Running this test concurrently
	// with other tests that use the shared factory would cause race conditions.
	// Go tests are sequential by default unless t.Parallel() is called.

	// Save and restore the shared factory state to avoid cross-test pollution.
	oldShared := sharedFactory
	oldInit := sharedFactoryInit
	t.Cleanup(func() {
		sharedFactory = oldShared
		sharedFactoryInit = oldInit
	})

	// Reset both sharedFactory and sharedFactoryInit to ensure consistent state.
	sharedFactory = &factory{constructors: make(map[string]IssuerConstructor)}
	sharedFactoryInit = sync.Once{}

	// Create a local factory with no constructors and register locally.
	fLocal := NewFactoryWithConstructors(&controller.Context{}, nil)
	fLocal.RegisterIssuer(apiutil.IssuerSelfSigned, dummyCtor)

	if _, err := fLocal.IssuerFor(newSelfSignedIssuer()); err != nil {
		t.Fatalf("expected local registration to resolve issuer, got error: %v", err)
	}

	// A different isolated factory should not see the local registration.
	fOther := NewFactoryWithConstructors(&controller.Context{}, nil)
	if _, err := fOther.IssuerFor(newSelfSignedIssuer()); err == nil {
		t.Fatalf("expected error for unregistered issuer in other factory, got nil")
	}
}
