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

package http

import (
	"testing"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

const (
	defaultTestNamespace = gen.DefaultTestNamespace
)

type solverFixture struct {
	// The Solver under test
	Solver *Solver
	*test.Builder

	// Challenge resource to use during tests
	Challenge *cmacme.Challenge

	// PreFn will run before the test is run, but after the fixture has been initialised.
	// This is useful if you want to load the clientset with some resources *after* the
	// fixture has been created.
	PreFn func(*testing.T, *solverFixture)
	// CheckFn should perform checks to ensure the output of the test is as expected.
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
	if s.testResources == nil {
		s.testResources = map[string]interface{}{}
	}
	if s.Builder == nil {
		s.Builder = &test.Builder{}
	}
	if s.Builder.T == nil {
		s.Builder.T = t
	}
	s.Builder.Init()
	var err error
	s.Solver, err = buildFakeSolver(s.Builder)
	if err != nil {
		t.Fatal(err)
	}
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

func buildFakeSolver(b *test.Builder) (*Solver, error) {
	b.Init()
	s, err := NewSolver(b.Context)
	if err != nil {
		return nil, err
	}
	b.Start()
	return s, nil
}

func strPtr(s string) *string {
	return &s
}
