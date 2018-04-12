package http

import (
	"testing"

	"github.com/jetstack/cert-manager/test/util/generate"

	"k8s.io/apimachinery/pkg/runtime"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/unit"
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

	// List of Kubernetes resources to pre-load into the clientset
	KubeObjects []runtime.Object
	// List of cert manager resources to pre-load into the clientset
	CMObjects []runtime.Object
	// Issuer that should be set on the Solver (a default will be used if nil)
	Issuer v1alpha1.GenericIssuer
	// Certificate resource to use during tests
	Certificate *v1alpha1.Certificate
	// Challenge resource to use during tests
	Challenge v1alpha1.ACMEOrderChallenge

	// PreFn will run before the test is run, but after the fixture has been initialised.
	// This is useful if you want to load the clientset with some resources *after* the
	// fixture has been created.
	PreFn func(*solverFixture)
	// CheckFn should performs checks to ensure the output of the test is as expected.
	// Optional additional values may be provided, which represent the output of the
	// function under test.
	CheckFn func(*solverFixture, ...interface{})
	// Err should be true if an error is expected from the function under test
	Err bool
	// Namespace is an optional namespace to operate within. If not set, a default
	// will be used.
	Namespace string

	// f is the integration test fixture being used for this test
	f *unit.Fixture

	// testResources is used to store references to resources used or created during
	// the test.
	testResources map[string]interface{}
}

func (s *solverFixture) Setup(t *testing.T) {
	if s.Issuer == nil {
		s.Issuer = generate.Issuer(generate.IssuerConfig{
			Name:      defaultTestIssuerName,
			Namespace: defaultTestNamespace,
		})
	}
	if s.Namespace == "" {
		s.Namespace = defaultTestNamespace
	}
	if s.testResources == nil {
		s.testResources = map[string]interface{}{}
	}
	s.f = &unit.Fixture{
		T:                  t,
		KubeObjects:        s.KubeObjects,
		CertManagerObjects: s.CMObjects,
	}
	// start the fixture to initialise the informer factories
	s.f.Start()
	s.Solver = buildFakeSolver(s.f, s.Issuer)
	if s.PreFn != nil {
		s.PreFn(s)
		s.f.Sync()
	}
}

func (s *solverFixture) Finish(t *testing.T, args ...interface{}) {
	defer s.f.Stop()
	// resync listers before running checks
	s.f.Sync()
	// run custom checks
	if s.CheckFn != nil {
		s.CheckFn(s, args...)
	}
}

func buildFakeSolver(f *unit.Fixture, issuer v1alpha1.GenericIssuer) *Solver {
	s := &Solver{
		issuer:        issuer,
		client:        f.KubeClient(),
		podLister:     f.KubeInformerFactory().Core().V1().Pods().Lister(),
		serviceLister: f.KubeInformerFactory().Core().V1().Services().Lister(),
		ingressLister: f.KubeInformerFactory().Extensions().V1beta1().Ingresses().Lister(),
	}
	f.Sync()
	return s
}

func strPtr(s string) *string {
	return &s
}
