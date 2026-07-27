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

package dns

import (
	"context"
	"errors"
	"testing"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/acmedns"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/akamai"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/azuredns"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/clouddns"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/cloudflare"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/digitalocean"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/route53"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

type solverFixture struct {
	// The Solver under test
	Solver *Solver
	*test.Builder

	// Challenge resource to use during tests
	Challenge *cmacme.Challenge

	dnsProviders *fakeDNSProviders

	// PreFn will run before the test is run, but after the fixture has been initialised.
	// This is useful if you want to load the clientset with some resources *after* the
	// fixture has been created.
	PreFn func(*testing.T, *solverFixture)
	// CheckFn should perform checks to ensure the output of the test is as expected.
	// Optional additional values may be provided, which represent the output of the
	// function under test.
	CheckFn func(*testing.T, *solverFixture, ...any)
	// Err should be true if an error is expected from the function under test
	Err bool

	// testResources is used to store references to resources used or created during
	// the test.
	testResources map[string]any
}

func (s *solverFixture) Setup(t *testing.T) {
	if s.testResources == nil {
		s.testResources = map[string]any{}
	}
	if s.Builder == nil {
		s.Builder = &test.Builder{}
	}
	if s.Builder.T == nil {
		s.Builder.T = t
	}
	if s.Builder.Context == nil {
		s.Builder.Context = &controller.Context{}
	}
	if len(s.Builder.Context.DNS01Nameservers) == 0 {
		s.Builder.Context.DNS01Nameservers = util.RecursiveNameservers
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

func (s *solverFixture) Finish(t *testing.T, args ...any) {
	defer s.Builder.Stop()
	// resync listers before running checks
	s.Builder.Sync()
	// run custom checks
	if s.CheckFn != nil {
		s.CheckFn(t, s, args...)
	}
}

func buildFakeSolver(b *test.Builder, dnsProviders dnsProviderConstructors) *Solver {
	b.InitWithRESTConfig()
	s := &Solver{
		Context:                 b.Context,
		secretLister:            b.Context.KubeSharedInformerFactory.Secrets().Lister(),
		dnsProviderConstructors: dnsProviders,
	}
	b.Start()
	return s
}

type fakeDNSProviderCall struct {
	name string
	args []any
}

type fakeDNSProviders struct {
	constructors dnsProviderConstructors
	calls        []fakeDNSProviderCall
}

func (f *fakeDNSProviders) call(name string, args ...any) {
	f.calls = append(f.calls, fakeDNSProviderCall{name: name, args: args})
}

func newFakeDNSProviders() *fakeDNSProviders {
	f := &fakeDNSProviders{
		calls: []fakeDNSProviderCall{},
	}
	f.constructors = dnsProviderConstructors{
		akamai: func(ctx context.Context, options ...akamai.DNSProviderOption) (*akamai.DNSProvider, error) {
			var opt akamai.DNSProviderOptions
			for _, o := range options {
				o.ApplyToDNSProviderOptions(&opt)
			}
			f.call("akamai", opt)
			return nil, nil
		},
		cloudDNS: func(ctx context.Context, options ...clouddns.DNSProviderOption) (*clouddns.DNSProvider, error) {
			var opt clouddns.DNSProviderOptions
			for _, o := range options {
				o.ApplyToDNSProviderOptions(&opt)
			}
			f.call("clouddns", opt)
			return nil, nil
		},
		cloudFlare: func(ctx context.Context, options ...cloudflare.DNSProviderOption) (*cloudflare.DNSProvider, error) {
			var opt cloudflare.DNSProviderOptions
			for _, o := range options {
				o.ApplyToDNSProviderOptions(&opt)
			}
			f.call("cloudflare", opt)
			if opt.Email == "" || (opt.APIKey == "" && opt.APIToken == "") {
				return nil, errors.New("invalid email or apikey or apitoken")
			}
			return nil, nil
		},
		route53: func(ctx context.Context, options ...route53.DNSProviderOption) (*route53.DNSProvider, error) {
			var opt route53.DNSProviderOptions
			for _, o := range options {
				o.ApplyToDNSProviderOptions(&opt)
			}
			f.call("route53", opt)
			return nil, nil
		},
		azureDNS: func(ctx context.Context, options ...azuredns.DNSProviderOption) (*azuredns.DNSProvider, error) {
			var opt azuredns.DNSProviderOptions
			for _, o := range options {
				o.ApplyToDNSProviderOptions(&opt)
			}
			f.call("azuredns", opt)
			return nil, nil
		},
		acmeDNS: func(ctx context.Context, options ...acmedns.DNSProviderOption) (*acmedns.DNSProvider, error) {
			var opt acmedns.DNSProviderOptions
			for _, o := range options {
				o.ApplyToDNSProviderOptions(&opt)
			}
			f.call("acmedns", opt)
			return nil, nil
		},
		digitalOcean: func(ctx context.Context, options ...digitalocean.DNSProviderOption) (*digitalocean.DNSProvider, error) {
			var opt digitalocean.DNSProviderOptions
			for _, o := range options {
				o.ApplyToDNSProviderOptions(&opt)
			}
			f.call("digitalocean", opt)
			return nil, nil
		},
	}
	return f
}
