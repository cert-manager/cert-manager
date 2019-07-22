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

package ca

import (
	"context"
	"testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/util"
)

const (
	defaultTestAcmeClusterResourceNamespace = "default"
	defaultTestSolverImage                  = "fake-solver-image"
)

type caFixture struct {
	CA *CA
	*test.Builder

	Certificate        *v1alpha1.Certificate
	CertificateRequest *v1alpha1.CertificateRequest

	ExpectedEvents []string

	PreFn   func(*testing.T, *caFixture)
	CheckFn func(*testing.T, *caFixture, ...interface{})
	Err     bool

	Ctx context.Context
}

func (s *caFixture) Setup(t *testing.T) {
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
	if s.Builder.T == nil {
		s.Builder.T = t
	}
	s.CA = s.buildFakeCA(s.Builder)
	if s.PreFn != nil {
		s.PreFn(t, s)
		s.Builder.Sync()
	}
}

func (s *caFixture) Finish(t *testing.T, args ...interface{}) {
	defer s.Builder.Stop()
	if err := s.Builder.AllActionsExecuted(); err != nil {
		t.Errorf(err.Error())
	}

	if !util.EqualSorted(s.ExpectedEvents, s.Events()) {
		t.Errorf("got unexpected events, exp='%s' got='%s'",
			s.ExpectedEvents, s.Events())
	}

	// resync listers before running checks
	s.Builder.Sync()
	// run custom checks
	if s.CheckFn != nil {
		s.CheckFn(t, s, args...)
	}
}

func (s *caFixture) buildFakeCA(b *test.Builder) *CA {
	b.Start()
	a := NewCA(b.Context)
	b.Sync()
	return a
}
