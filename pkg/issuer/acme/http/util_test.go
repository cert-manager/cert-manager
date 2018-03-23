package http

import (
	"testing"

	"github.com/jetstack/cert-manager/test/util/generate"

	extv1beta1 "k8s.io/api/extensions/v1beta1"
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
	CMObjects   []runtime.Object
	// Issuer that should be set on the Solver (a default will be used if nil)
	Issuer      v1alpha1.GenericIssuer
	// Optional certificate resource to use during tests
	Certificate *v1alpha1.Certificate
	// Optional domain to be used during tests
	Domain      string
	// Optional token to be used during tests
	Token       string
	// Optional key to be used during tests
	Key         string
	// PreFn will run before the test is run, but after the fixture has been initialised.
	// This is useful if you want to load the clientset with some resources *after* the
	// fixture has been created.
	PreFn       func(*solverFixture)
	// CheckFn should performs checks to ensure the output of the test is as expected
	CheckFn     func(*solverFixture)
	// Err should be true if an error is expected from the function under test
	Err         bool
	// Namespace is an optional namespace to operate within. If not set, a default
	// will be used.
	Namespace   string

	// f is the integration test fixture being used for this test
	f *unit.Fixture
	// createdIngress is used to store a reference to an ingress resource created
	// during a tests PreFn. This should probably be removed in order to further
	// generalise this test fixture
	createdIngress *extv1beta1.Ingress
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

func (s *solverFixture) Finish(t *testing.T) {
	defer s.f.Stop()
	// resync listers before running checks
	s.f.Sync()
	// run custom checks
	if s.CheckFn != nil {
		s.CheckFn(s)
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
