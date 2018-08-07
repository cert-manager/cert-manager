package acme

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"

	"github.com/jetstack/cert-manager/pkg/acme/client"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/unit"
)

const (
	defaultTestAcmeClusterResourceNamespace = "default"
	defaultTestSolverImage                  = "fake-solver-image"
)

type acmeFixture struct {
	Acme *Acme

	KubeObjects []runtime.Object
	CMObjects   []runtime.Object
	Issuer      v1alpha1.GenericIssuer
	Certificate *v1alpha1.Certificate
	Client      *client.FakeACME

	PreFn   func(*acmeFixture)
	CheckFn func(*acmeFixture, ...interface{})
	Err     bool

	Ctx context.Context

	// f is the integration test fixture being used for this test
	f *unit.Fixture
}

func (s *acmeFixture) Setup(t *testing.T) {
	if s.Client == nil {
		s.Client = &client.FakeACME{}
	}
	if s.Ctx == nil {
		s.Ctx = context.Background()
	}
	s.f = &unit.Fixture{
		T:                  t,
		KubeObjects:        s.KubeObjects,
		CertManagerObjects: s.CMObjects,
	}
	// start the fixture to initialise the informer factories
	s.f.Start()
	s.Acme = buildFakeAcme(s.f, s.Client, s.Issuer)
	if s.PreFn != nil {
		s.PreFn(s)
		s.f.Sync()
	}
}

func (s *acmeFixture) Finish(t *testing.T, args ...interface{}) {
	defer s.f.Stop()
	// resync listers before running checks
	s.f.Sync()
	// run custom checks
	if s.CheckFn != nil {
		s.CheckFn(s, args...)
	}
}

func buildFakeAcme(f *unit.Fixture, client *client.FakeACME, issuer v1alpha1.GenericIssuer) *Acme {
	a, err := New(issuer,
		f.KubeClient(),
		f.CertManagerClient(),
		f.EventRecorder(),
		defaultTestAcmeClusterResourceNamespace,
		defaultTestSolverImage,
		f.KubeInformerFactory().Core().V1().Secrets().Lister(),
		f.KubeInformerFactory().Core().V1().Pods().Lister(),
		f.KubeInformerFactory().Core().V1().Services().Lister(),
		f.KubeInformerFactory().Extensions().V1beta1().Ingresses().Lister(),
		// TODO: support overriding this field
		false,
		[]string{"8.8.8.8:53"},
	)
	if err != nil {
		f.T.Errorf("error creating fake Acme: %v", err)
		f.T.FailNow()
	}
	f.Sync()
	return a.(*Acme)
}
