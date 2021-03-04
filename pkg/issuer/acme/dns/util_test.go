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
	"errors"
	"testing"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/acmedns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/azuredns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/clouddns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/cloudflare"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/digitalocean"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/route53"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

const (
	defaultTestIssuerName = "test-issuer"
)

type solverFixture struct {
	// The Solver under test
	Solver *Solver
	*test.Builder

	// Issuer to be passed to functions on the Solver (a default will be used if nil)
	Issuer v1.GenericIssuer
	// Challenge resource to use during tests
	Challenge *cmacme.Challenge

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
		s.Issuer = gen.Issuer(defaultTestIssuerName, gen.SetIssuerACME(cmacme.ACMEIssuer{}))
	}
	if s.testResources == nil {
		s.testResources = map[string]interface{}{}
	}
	if s.Builder == nil {
		s.Builder = &test.Builder{}
	}
	if s.Builder.T == nil {
		s.Builder.T = t
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
	b.Init()
	s := &Solver{
		Context:                 b.Context,
		secretLister:            b.Context.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		dnsProviderConstructors: dnsProviders,
	}
	b.Start()
	return s
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
		cloudDNS: func(project string, serviceAccount []byte, dns01Nameservers []string, ambient bool, hostedZoneName string) (*clouddns.DNSProvider, error) {
			f.call("clouddns", project, serviceAccount, util.RecursiveNameservers, ambient, hostedZoneName)
			return nil, nil
		},
		cloudFlare: func(email, apikey, apiToken string, dns01Nameservers []string) (*cloudflare.DNSProvider, error) {
			f.call("cloudflare", email, apikey, apiToken, util.RecursiveNameservers)
			if email == "" || (apikey == "" && apiToken == "") {
				return nil, errors.New("invalid email or apikey or apitoken")
			}
			return nil, nil
		},
		route53: func(accessKey, secretKey, hostedZoneID, region, role string, ambient bool, dns01Nameservers []string) (*route53.DNSProvider, error) {
			f.call("route53", accessKey, secretKey, hostedZoneID, region, role, ambient, util.RecursiveNameservers)
			return nil, nil
		},
		azureDNS: func(environment, clientID, clientSecret, subscriptionID, tenantID, resourceGroupName, hostedZoneName string, dns01Nameservers []string, ambient bool) (*azuredns.DNSProvider, error) {
			f.call("azuredns", clientID, clientSecret, subscriptionID, tenantID, resourceGroupName, hostedZoneName, util.RecursiveNameservers, ambient)
			return nil, nil
		},
		acmeDNS: func(host string, accountJson []byte, dns01Nameservers []string) (*acmedns.DNSProvider, error) {
			f.call("acmedns", host, accountJson, dns01Nameservers)
			return nil, nil
		},
		digitalOcean: func(token string, dns01Nameservers []string) (*digitalocean.DNSProvider, error) {
			f.call("digitalocean", token, util.RecursiveNameservers)
			return nil, nil
		},
	}
	return f
}
