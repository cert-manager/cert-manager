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

package http

import (
	"testing"

	"github.com/jetstack/cert-manager/test/util/generate"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller/test"
)

const (
	defaultTestIssuerName              = "test-issuer"
	defaultTestIssuerKind              = v1alpha1.IssuerKind
	defaultTestNamespace               = "default"
	defaultTestCertificateName         = "test-cert"
	defaultTestCertificateIngressClass = "nginx"
)

type solverFixture struct {
	// The Solver under test
	Solver *Solver
	*test.Builder

	// Issuer to be passed to functions on the Solver (a default will be used if nil)
	Issuer v1alpha1.GenericIssuer
	// Challenge resource to use during tests
	Challenge *v1alpha1.Challenge

	// PreFn will run before the test is run, but after the fixture has been initialised.
	// This is useful if you want to load the clientset with some resources *after* the
	// fixture has been created.
	PreFn func(*testing.T, *solverFixture)
	// CheckFn should performs checks to ensure the output of the test is as expected.
	// Optional additional values may be provided, which represent the output of the
	// function under test.
	CheckFn func(*testing.T, *solverFixture, ...interface{})
	// Err should be true if an error is expected from the function under test
	Err bool

	// testResources is used to store references to resources used or created during
	// the test.
	testResources map[string]interface{}
}

func (s *solverFixture) Setup(t *testing.T) {
	if s.Issuer == nil {
		s.Issuer = generate.Issuer(generate.IssuerConfig{
			Name:      defaultTestIssuerName,
			Namespace: defaultTestNamespace,
			HTTP01:    &v1alpha1.ACMEIssuerHTTP01Config{},
		})
	}
	if s.testResources == nil {
		s.testResources = map[string]interface{}{}
	}
	if s.Builder == nil {
		s.Builder = &test.Builder{}
	}
	if s.Builder.T == nil {
		s.Builder.T = t
	}
	s.Builder.Start()
	s.Solver = buildFakeSolver(s.Builder)
	if s.PreFn != nil {
		s.PreFn(t, s)
		s.Builder.Sync()
	}
}

func (s *solverFixture) Finish(t *testing.T, args ...interface{}) {
	defer s.Builder.Stop()
	// resync listers before running checks
	s.Builder.Sync()
	// run custom checks
	if s.CheckFn != nil {
		s.CheckFn(t, s, args...)
	}
}

func buildFakeSolver(b *test.Builder) *Solver {
	b.Start()
	s := NewSolver(b.Context)
	b.Sync()
	return s
}

func strPtr(s string) *string {
	return &s
}
