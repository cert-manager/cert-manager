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

package scheduler

import (
	"context"
	"testing"

	"github.com/jetstack/cert-manager/pkg/controller/test"
)

func (f *fixture) Setup(t *testing.T) {
	if f.Ctx == nil {
		f.Ctx = context.Background()
	}
	if f.Builder == nil {
		f.Builder = &test.Builder{}
	}
	f.Controller = f.buildFakeController(f.Builder)
	if f.PreFn != nil {
		f.PreFn(t, f)
		f.Builder.Sync()
	}
}

func (f *fixture) Finish(t *testing.T, args ...interface{}) {
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

func (f *fixture) buildFakeController(b *test.Builder) *Controller {
	b.Start()
	c := New(b.Context)
	b.Sync()
	return c
}
