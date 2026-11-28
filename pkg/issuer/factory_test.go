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

func TestNewFactoryWithConstructors(t *testing.T) {
	t.Parallel()

	f := NewFactoryWithConstructors(&controller.Context{}, map[string]IssuerConstructor{
		apiutil.IssuerSelfSigned: dummyCtor,
	})
	if _, err := f.IssuerFor(newSelfSignedIssuer()); err != nil {
		t.Fatalf("expected provided constructor to resolve issuer, got error: %v", err)
	}

	empty := NewFactoryWithConstructors(&controller.Context{}, nil)
	if _, err := empty.IssuerFor(newSelfSignedIssuer()); err == nil {
		t.Fatal("expected error for unregistered issuer, got nil")
	}
}

func TestNewFactoryWithConstructors_CopiesInput(t *testing.T) {
	t.Parallel()

	ctors := map[string]IssuerConstructor{}
	f := NewFactoryWithConstructors(&controller.Context{}, ctors)
	ctors[apiutil.IssuerSelfSigned] = dummyCtor

	if _, err := f.IssuerFor(newSelfSignedIssuer()); err == nil {
		t.Fatal("expected later changes to the input map not to affect the factory")
	}
}

func TestSnapshot_IsolatedFromLaterRegistrations(t *testing.T) {
	t.Parallel()

	registry := &factory{constructors: map[string]IssuerConstructor{}}
	before := registry.snapshot(&controller.Context{})
	registry.register(apiutil.IssuerSelfSigned, dummyCtor)
	after := registry.snapshot(&controller.Context{})

	if _, err := before.IssuerFor(newSelfSignedIssuer()); err == nil {
		t.Fatal("expected snapshot taken before registration not to see the issuer")
	}
	if _, err := after.IssuerFor(newSelfSignedIssuer()); err != nil {
		t.Fatalf("expected snapshot taken after registration to see the issuer, got error: %v", err)
	}
}
