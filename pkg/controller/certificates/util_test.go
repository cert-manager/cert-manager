/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package certificates

import (
	"context"
	"testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller/test"
)

type controllerFixture struct {
	Controller *Controller
	*test.Builder

	Issuer      v1alpha1.GenericIssuer
	Certificate v1alpha1.Certificate

	PreFn   func(*testing.T, *controllerFixture)
	CheckFn func(*testing.T, *controllerFixture, ...interface{})
	Err     bool

	Ctx context.Context
}

func (f *controllerFixture) Setup(t *testing.T) {
	if f.Issuer == nil {
		f.Issuer = &v1alpha1.Issuer{}
	}
	if f.Ctx == nil {
		f.Ctx = context.Background()
	}
	if f.Builder == nil {
		// TODO: set default IssuerOptions
		//		defaultTestAcmeClusterResourceNamespace,
		//		defaultTestSolverImage,
		//		default dns01 nameservers
		//		ambient credentials settings
		f.Builder = &test.Builder{}
	}
	f.Controller = f.buildFakeController(f.Builder, f.Issuer)
	if f.PreFn != nil {
		f.PreFn(t, f)
		f.Builder.Sync()
	}
}

func (f *controllerFixture) Finish(t *testing.T, args ...interface{}) {
	defer f.Builder.Stop()
	if err := f.Builder.AllReactorsCalled(); err != nil {
		t.Errorf("Not all expected reactors were called: %v", err)
	}
	if err := f.Builder.AllActionsExecuted(); err != nil {
		t.Errorf(err.Error())
	}

	// resync listers before running checks
	f.Builder.Sync()
	// run custom checks
	if f.CheckFn != nil {
		f.CheckFn(t, f, args...)
	}
}

func (f *controllerFixture) buildFakeController(b *test.Builder, issuer v1alpha1.GenericIssuer) *Controller {
	b.Start()
	c := New(b.Context)
	c.helper = f
	b.Sync()
	return c
}

func (f *controllerFixture) GetGenericIssuer(ref v1alpha1.ObjectReference, ns string) (v1alpha1.GenericIssuer, error) {
	return f.Issuer, nil
}
