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
	"fmt"
	"testing"
	"time"

	realclock "k8s.io/utils/clock"
	clock "k8s.io/utils/clock/testing"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

type controllerFixture struct {
	Controller *controller
	*test.Builder

	Issuer      v1alpha1.GenericIssuer
	Certificate v1alpha1.Certificate
	IssuerImpl  issuer.Interface
	Clock       *clock.FakeClock

	// StaticTemporaryCert will be used as the 'localTemporarySigner' response
	StaticTemporaryCert []byte

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

	// Fix the clock used in apiutil so that calls to set status conditions
	// can be predictably tested
	apiutil.Clock = f.Controller.clock
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

	// Reset the clock used in apiutil back to the real system clock
	apiutil.Clock = realclock.RealClock{}
}

func (f *controllerFixture) buildFakeController(b *test.Builder, issuer v1alpha1.GenericIssuer) *controller {
	b.Start()
	c := &controller{}
	c.Register(b.Context)
	c.helper = f
	c.issuerFactory = f
	c.localTemporarySigner = f.localTemporarySigner
	c.clock = f.Clock
	if c.clock == nil {
		c.clock = clock.NewFakeClock(time.Now())
	}
	b.Sync()
	return c
}

func (f *controllerFixture) GetGenericIssuer(ref v1alpha1.ObjectReference, ns string) (v1alpha1.GenericIssuer, error) {
	return f.Issuer, nil
}

func (f *controllerFixture) IssuerFor(v1alpha1.GenericIssuer) (issuer.Interface, error) {
	return f.IssuerImpl, nil
}

// localTemporarySigner returns a fixed static certificate that can be compared
// against in tests.
func (f *controllerFixture) localTemporarySigner(crt *v1alpha1.Certificate, pk []byte) ([]byte, error) {
	if f.StaticTemporaryCert == nil {
		return nil, fmt.Errorf("localTemporarySigner not implemented")
	}
	return f.StaticTemporaryCert, nil
}
