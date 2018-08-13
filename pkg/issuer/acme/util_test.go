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

package acme

import (
	"context"
	"testing"

	"github.com/jetstack/cert-manager/pkg/acme/client"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller/test"
)

const (
	defaultTestAcmeClusterResourceNamespace = "default"
	defaultTestSolverImage                  = "fake-solver-image"
)

type acmeFixture struct {
	Acme *Acme
	*test.Builder

	Issuer      v1alpha1.GenericIssuer
	Certificate *v1alpha1.Certificate
	Client      *client.FakeACME

	PreFn   func(*acmeFixture)
	CheckFn func(*acmeFixture, ...interface{})
	Err     bool

	Ctx context.Context
}

func (s *acmeFixture) Setup(t *testing.T) {
	if s.Client == nil {
		s.Client = &client.FakeACME{}
	}
	if s.Ctx == nil {
		s.Ctx = context.Background()
	}
	if s.Builder == nil {
		// TODO: set default IssuerOptions
		//		defaultTestAcmeClusterResourceNamespace,
		//		defaultTestSolverImage,
		//		default dns01 nameservers
		//		ambient credentials settings
		s.Builder = &test.Builder{}
	}
	s.Acme = buildFakeAcme(s.Builder, s.Issuer)
	if s.PreFn != nil {
		s.PreFn(s)
		s.Builder.Sync()
	}
}

func (s *acmeFixture) Finish(t *testing.T, args ...interface{}) {
	defer s.Builder.Stop()
	// resync listers before running checks
	s.Builder.Sync()
	// run custom checks
	if s.CheckFn != nil {
		s.CheckFn(s, args...)
	}
}

func buildFakeAcme(b *test.Builder, issuer v1alpha1.GenericIssuer) *Acme {
	b.Start()
	a, err := New(b.Context, issuer)
	if err != nil {
		panic("error creating fake Acme: %v" + err.Error())
	}
	b.Sync()
	return a.(*Acme)
}
