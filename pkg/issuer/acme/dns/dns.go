/*
Copyright 2019 The Jetstack cert-manager contributors.

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
	"encoding/json"
	"fmt"
	"time"

	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/acme/webhook"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/acmedns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/akamai"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/azuredns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/clouddns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/cloudflare"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/digitalocean"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/rfc2136"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/route53"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	webhookslv "github.com/jetstack/cert-manager/pkg/issuer/acme/dns/webhook"
)

// Solver is a solver for the acme dns01 challenge.
// Given a Certificate object, it determines the correct DNS provider based on
// the certificate, and configures it based on the referenced issuer.
type Solver struct {
	*controller.Context

	providers map[string]webhook.Solver
}

// NewSolver creates a Solver which can instantiate the appropriate DNS
// provider.
func NewSolver(ctx *controller.Context) (*Solver, error) {
	dnsSolvers := []webhook.Solver{
		&acmedns.Solver{},
		&akamai.Solver{},
		&azuredns.Solver{},
		&clouddns.Solver{},
		&cloudflare.Solver{},
		&digitalocean.Solver{},
		&rfc2136.Solver{},
		&route53.Solver{},
		&webhookslv.Webhook{},
	}

	initialized := make(map[string]webhook.Solver)
	// initialize all DNS providers
	for _, s := range dnsSolvers {
		err := s.Initialize(ctx.RESTConfig, ctx.StopCh)
		if err != nil {
			return nil, fmt.Errorf("error intializing DNS provider %q: %v", s.Name(), err)
		}
		initialized[s.Name()] = s
	}

	return &Solver{
		Context:   ctx,
		providers: initialized,
	}, nil
}

// Present performs the work to configure DNS to resolve a DNS01 challenge.
func (s *Solver) Present(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	if ch.Spec.Config.DNS01 == nil {
		return fmt.Errorf("challenge dns config must be specified")
	}

	solver, req, err := s.prepareChallengeRequest(issuer, ch)
	if err != nil {
		return err
	}

	klog.Infof("Presenting DNS01 challenge for domain %q", ch.Spec.DNSName)
	return solver.Present(req)
}

// Check verifies that the DNS records for the ACME challenge have propagated.
func (s *Solver) Check(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	fqdn, err := util.DNS01LookupFQDN(ch.Spec.DNSName, false, s.DNS01Nameservers...)
	if err != nil {
		return err
	}

	klog.Infof("Checking DNS propagation for %q using name servers: %v", ch.Spec.DNSName, s.Context.DNS01Nameservers)

	ok, err := util.PreCheckDNS(fqdn, ch.Spec.Key, s.Context.DNS01Nameservers,
		s.Context.DNS01CheckAuthoritative)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("DNS record for %q not yet propagated", ch.Spec.DNSName)
	}

	ttl := 60
	klog.Infof("Waiting DNS record TTL (%ds) to allow propagation of DNS record for domain %q", ttl, fqdn)
	time.Sleep(time.Second * time.Duration(ttl))
	klog.Infof("ACME DNS01 validation record propagated for %q", fqdn)

	return nil
}

// CleanUp removes DNS records which are no longer needed after
// certificate issuance.
func (s *Solver) CleanUp(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	if ch.Spec.Config.DNS01 == nil {
		return fmt.Errorf("challenge dns config must be specified")
	}

	solver, req, err := s.prepareChallengeRequest(issuer, ch)
	if err != nil {
		return err
	}

	klog.Infof("Cleaning up DNS01 challenge for domain %q", ch.Spec.DNSName)
	return solver.Present(req)
}

func (s *Solver) prepareChallengeRequest(issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) (webhook.Solver, *v1alpha1.ChallengeRequest, error) {
	dns01Config, err := s.dns01ConfigForChallenge(issuer, ch)
	if err != nil {
		return nil, nil, err
	}

	webhookSolver, cfg, err := s.dns01SolverForConfig(dns01Config)
	if err != nil {
		return nil, nil, err
	}

	fqdn, err := util.DNS01LookupFQDN(ch.Spec.DNSName, followCNAME(dns01Config.CNAMEStrategy), s.DNS01Nameservers...)
	if err != nil {
		return nil, nil, err
	}

	zone, err := util.FindZoneByFqdn(fqdn, s.DNS01Nameservers)
	if err != nil {
		return nil, nil, err
	}

	resourceNamespace := s.ResourceNamespace(issuer)
	canUseAmbientCredentials := s.CanUseAmbientCredentials(issuer)

	// construct a ChallengeRequest which can be passed to DNS solvers.
	// The provided config will be encoded to JSON in order to avoid a coupling
	// between cert-manager and any particular DNS provider implementation.
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, nil, err
	}

	req := &v1alpha1.ChallengeRequest{
		Type:                    "dns-01",
		ResolvedFQDN:            fqdn,
		ResolvedZone:            zone,
		AllowAmbientCredentials: canUseAmbientCredentials,
		ResourceNamespace:       resourceNamespace,
		Key:                     ch.Spec.Key,
		Config:                  &apiext.JSON{Raw: b},
	}

	return webhookSolver, req, nil
}

func followCNAME(strategy v1alpha1.CNAMEStrategy) bool {
	if strategy == v1alpha1.FollowStrategy {
		return true
	}
	return false
}

func (s *Solver) dns01SolverForConfig(config *v1alpha1.ACMEIssuerDNS01Provider) (webhook.Solver, interface{}, error) {
	solverName := ""
	var c interface{}
	switch {
	case config.AcmeDNS != nil:
		solverName = "acmedns"
		c = config.AcmeDNS
	case config.Akamai != nil:
		solverName = "akamai"
		c = config.Akamai
	case config.AzureDNS != nil:
		solverName = "azuredns"
		c = config.AzureDNS
	case config.CloudDNS != nil:
		solverName = "clouddns"
		c = config.CloudDNS
	case config.Cloudflare != nil:
		solverName = "cloudflare"
		c = config.Cloudflare
	case config.DigitalOcean != nil:
		solverName = "digitalocean"
		c = config.DigitalOcean
	case config.RFC2136 != nil:
		solverName = "rfc2136"
		c = config.RFC2136
	case config.Route53 != nil:
		solverName = "route53"
		c = config.Route53
	case config.Webhook != nil:
		solverName = "webhook"
		c = config.Webhook
	}
	if solverName == "" {
		return nil, nil, fmt.Errorf("failed to determine DNS01 solver type")
	}
	p := s.providers[solverName]
	if p == nil {
		return nil, c, fmt.Errorf("no solver provider configured for %q", solverName)
	}
	return p, c, nil
}

func (s *Solver) dns01ConfigForChallenge(issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) (*v1alpha1.ACMEIssuerDNS01Provider, error) {
	providerName := ch.Spec.Config.DNS01.Provider
	if providerName == "" {
		return nil, fmt.Errorf("dns01 challenge provider name must be set")
	}

	dns01Config, err := issuer.GetSpec().ACME.DNS01.Provider(providerName)
	if err != nil {
		return nil, err
	}

	return dns01Config, nil
}
