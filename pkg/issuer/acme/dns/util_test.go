package dns

import (
	"errors"
	"testing"

	"github.com/jetstack/cert-manager/test/util/generate"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/azuredns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/clouddns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/cloudflare"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/route53"
)

const (
	defaultTestIssuerName      = "test-issuer"
	defaultTestIssuerKind      = v1alpha1.IssuerKind
	defaultTestNamespace       = "default"
	defaultTestCertificateName = "test-cert"
)

type solverFixture struct {
	// The Solver under test
	Solver *Solver
	*test.Builder

	// Issuer to be passed to functions on the Solver (a default will be used if nil)
	Issuer v1alpha1.GenericIssuer
	// Certificate resource to use during tests
	Certificate *v1alpha1.Certificate
	// Challenge resource to use during tests
	Challenge v1alpha1.ACMEOrderChallenge

	dnsProviders *fakeDNSProviders

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
		})
	}
	if s.testResources == nil {
		s.testResources = map[string]interface{}{}
	}
	if s.Builder == nil {
		s.Builder = &test.Builder{}
	}
	if s.dnsProviders == nil {
		s.dnsProviders = newFakeDNSProviders()
	}
	s.Solver = buildFakeSolver(s.Builder, s.dnsProviders.constructors)
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

func buildFakeSolver(b *test.Builder, dnsProviders dnsProviderConstructors) *Solver {
	b.Start()
	s := &Solver{
		Context:                 b.Context,
		secretLister:            b.Context.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		dnsProviderConstructors: dnsProviders,
	}
	b.Sync()
	return s
}

func strPtr(s string) *string {
	return &s
}

type fakeDNSProviderCall struct {
	name string
	args []interface{}
}

type fakeDNSProviders struct {
	constructors dnsProviderConstructors
	calls        []fakeDNSProviderCall
}

func (f *fakeDNSProviders) call(name string, args ...interface{}) {
	f.calls = append(f.calls, fakeDNSProviderCall{name: name, args: args})
}

func newFakeDNSProviders() *fakeDNSProviders {
	f := &fakeDNSProviders{
		calls: []fakeDNSProviderCall{},
	}
	f.constructors = dnsProviderConstructors{
		cloudDNS: func(project string, serviceAccount []byte) (*clouddns.DNSProvider, error) {
			f.call("clouddns", project, serviceAccount)
			return nil, nil
		},
		cloudFlare: func(email, apikey string) (*cloudflare.DNSProvider, error) {
			f.call("cloudflare", email, apikey)
			if email == "" || apikey == "" {
				return nil, errors.New("invalid email or apikey")
			}
			return nil, nil
		},
		route53: func(accessKey, secretKey, hostedZoneID, region string, ambient bool) (*route53.DNSProvider, error) {
			f.call("route53", accessKey, secretKey, hostedZoneID, region, ambient)
			return nil, nil
		},
		azureDNS: func(clientID, clientSecret, subscriptionID, tenentID, resourceGroupName, hostedZoneName string) (*azuredns.DNSProvider, error) {
			f.call("azuredns", clientID, clientSecret, subscriptionID, tenentID, resourceGroupName, hostedZoneName)
			return nil, nil
		},
	}
	return f
}
