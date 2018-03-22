package http

import (
	"testing"

	"github.com/jetstack/cert-manager/test/util/generate"

	extv1beta1 "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/integration"
)

const (
	defaultTestIssuerName              = "test-issuer"
	defaultTestIssuerKind              = v1alpha1.IssuerKind
	defaultTestNamespace               = "default"
	defaultTestCertificateName         = "test-cert"
	defaultTestCertificateIngressClass = "nginx"
)

type solverFixture struct {
	Solver *Solver

	KubeObjects []runtime.Object
	CMObjects   []runtime.Object
	Issuer      v1alpha1.GenericIssuer
	Certificate *v1alpha1.Certificate
	Domain      string
	Token       string
	Key         string
	PreFn       func(*solverFixture)
	CheckFn     func(*solverFixture)
	Err         bool
	Namespace   string

	// f is the integration test fixture being used for this test
	f *integration.Fixture
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
	s.f = &integration.Fixture{
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

func buildFakeSolver(f *integration.Fixture, issuer v1alpha1.GenericIssuer) *Solver {
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
