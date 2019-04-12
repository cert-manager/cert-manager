package dns

import (
	"encoding/json"
	"fmt"
	"strings"

	"k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	"github.com/jetstack/cert-manager/pkg/acme/webhook"
)

// Option applies a configuration option to the test fixture being built
type Option func(*fixture)

// NewFixture constructs a new *fixture, applying the given Options before
// returning.
func NewFixture(solver webhook.Solver, opts ...Option) *fixture {
	f := &fixture{
		testSolver: solver,
	}
	for _, o := range opts {
		o(f)
	}
	applyDefaults(f)
	return f
}

func applyDefaults(f *fixture) {
	if f.testDNSServer == "" {
		f.testDNSServer = "8.8.8.8:53"
	}
	if f.resolvedFQDN == "" {
		f.resolvedFQDN = "cert-manager-dns01-tests."+f.resolvedZone+"."
	}
}

func validate(f *fixture) error {
	var errs []error
	if f.resolvedFQDN == "" {
		errs = append(errs, fmt.Errorf("resolvedFQDN must be provided"))
	}
	if !strings.HasSuffix(f.resolvedFQDN, ".") {
		errs = append(errs, fmt.Errorf("resolvedFQDN must end with a '.'"))
	}
	if f.resolvedZone == "" {
		errs = append(errs, fmt.Errorf("resolvedZone must be provided"))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%v", errs)
	}

	return nil
}

func SetResolvedFQDN(s string) Option {
	return func(f *fixture) {
		f.resolvedFQDN = s
	}
}

func SetResolvedZone(s string) Option {
	return func(f *fixture) {
		f.resolvedZone = s
	}
}

func SetAllowAmbientCredentials(b bool) Option {
	return func(f *fixture) {
		f.allowAmbientCredentials = b
	}
}

func SetConfig(i interface{}) Option {
	return func(f *fixture) {
		d, err := json.Marshal(i)
		if err != nil {
			panic(err)
		}
		f.jsonConfig = &extapi.JSON{Raw: d}
	}
}

func SetStrict(s bool) Option {
	return func(f *fixture) {
		f.strictMode = s
	}
}

func AddSecretFixture(s *v1.Secret) Option {
	return func(f *fixture) {
		f.secretFixtures = append(f.secretFixtures, s)
	}
}

func SetDNSServer(s string) Option {
	return func(f *fixture) {
		f.testDNSServer = s
	}
}
