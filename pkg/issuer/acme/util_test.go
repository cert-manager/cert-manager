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
		s.Builder = &test.Builder{
			// TODO: set default IssuerOptions
			//		defaultTestAcmeClusterResourceNamespace,
			//		defaultTestSolverImage,
			//		default dns01 nameservers
			//		ambient credentials settings
		}
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
