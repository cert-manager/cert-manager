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

package venafi

import (
	"context"
	"testing"

	vfake "github.com/Venafi/vcert/pkg/venafi/fake"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller/test"
)

type fixture struct {
	Venafi *Venafi
	*test.Builder

	Issuer      v1alpha1.GenericIssuer
	Certificate *v1alpha1.Certificate
	Client      connector

	PreFn   func(*testing.T, *fixture)
	CheckFn func(*testing.T, *fixture, ...interface{})
	Err     bool

	Ctx context.Context
}

func (s *fixture) Setup(t *testing.T) {
	if s.Issuer == nil {
		s.Issuer = &v1alpha1.Issuer{
			Spec: v1alpha1.IssuerSpec{
				IssuerConfig: v1alpha1.IssuerConfig{
					Venafi: &v1alpha1.VenafiIssuer{},
				},
			},
		}
	}
	// if a custom client has not been provided, we will use the vcert fake
	// which generates certificates and private keys by default
	if s.Client == nil {
		s.Client = vfake.NewConnector(true, nil)
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
	s.Venafi = s.buildFakeVenafi(s.Builder, s.Issuer)
	if s.PreFn != nil {
		s.PreFn(t, s)
		s.Builder.Sync()
	}
}

func (s *fixture) Finish(t *testing.T, args ...interface{}) {
	defer s.Builder.Stop()
	if err := s.Builder.AllReactorsCalled(); err != nil {
		t.Errorf("Not all expected reactors were called: %v", err)
	}
	if err := s.Builder.AllActionsExecuted(); err != nil {
		t.Errorf(err.Error())
	}

	// resync listers before running checks
	s.Builder.Sync()
	// run custom checks
	if s.CheckFn != nil {
		s.CheckFn(t, s, args...)
	}
}

func (s *fixture) buildFakeVenafi(b *test.Builder, issuer v1alpha1.GenericIssuer) *Venafi {
	b.Start()
	// TODO: replace this with a call to NewVenafi by somehow modifying it to allow
	// injecting the fake venafi client.
	v := &Venafi{
		issuer:            issuer,
		Context:           s.Context,
		resourceNamespace: s.Context.IssuerOptions.ResourceNamespace(issuer),
		secretsLister:     s.Context.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		client:            s.Client,
	}
	b.Sync()
	return v
}
