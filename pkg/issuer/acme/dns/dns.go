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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	corev1listers "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack/cert-manager/pkg/acme/webhook"
	whapi "github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/acmedns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/akamai"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/azuredns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/clouddns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/cloudflare"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/digitalocean"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/hetzner"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/rfc2136"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/route53"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	webhookslv "github.com/jetstack/cert-manager/pkg/issuer/acme/dns/webhook"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

// solver is the old solver type interface.
// All new solvers should be implemented using the new webhook.Solver interface.
type solver interface {
	Present(domain, fqdn, value string) error
	CleanUp(domain, fqdn, value string) error
}

// dnsProviderConstructors defines how each provider may be constructed.
// It is useful for mocking out a given provider since an alternate set of
// constructors may be set.
type dnsProviderConstructors struct {
	cloudDNS     func(project string, serviceAccount []byte, dns01Nameservers []string, ambient bool, hostedZoneName string) (*clouddns.DNSProvider, error)
	cloudFlare   func(email, apikey, apiToken string, dns01Nameservers []string) (*cloudflare.DNSProvider, error)
	route53      func(accessKey, secretKey, hostedZoneID, region, role string, ambient bool, dns01Nameservers []string) (*route53.DNSProvider, error)
	azureDNS     func(environment, clientID, clientSecret, subscriptionID, tenantID, resourceGroupName, hostedZoneName string, dns01Nameservers []string, ambient bool) (*azuredns.DNSProvider, error)
	acmeDNS      func(host string, accountJson []byte, dns01Nameservers []string) (*acmedns.DNSProvider, error)
	digitalOcean func(token string, dns01Nameservers []string) (*digitalocean.DNSProvider, error)
	hetzner      func(token string, dns01Nameservers []string) (*hetzner.DNSProvider, error)
}

// Solver is a solver for the acme dns01 challenge.
// Given a Certificate object, it determines the correct DNS provider based on
// the certificate, and configures it based on the referenced issuer.
type Solver struct {
	*controller.Context
	secretLister            corev1listers.SecretLister
	dnsProviderConstructors dnsProviderConstructors
	webhookSolvers          map[string]webhook.Solver
}

// Present performs the work to configure DNS to resolve a DNS01 challenge.
func (s *Solver) Present(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error {
	log := logf.WithResource(logf.FromContext(ctx, "Present"), ch).WithValues("domain", ch.Spec.DNSName)
	ctx = logf.NewContext(ctx, log)

	webhookSolver, req, err := s.prepareChallengeRequest(issuer, ch)
	if err != nil && err != errNotFound {
		return err
	}
	if err == nil {
		log.V(logf.InfoLevel).Info("presenting DNS01 challenge for domain")
		return webhookSolver.Present(req)
	}

	slv, providerConfig, err := s.solverForChallenge(ctx, issuer, ch)
	if err != nil {
		return err
	}

	fqdn, err := util.DNS01LookupFQDN(ch.Spec.DNSName, followCNAME(providerConfig.CNAMEStrategy), s.DNS01Nameservers...)
	if err != nil {
		return err
	}

	log.V(logf.DebugLevel).Info("presenting DNS01 challenge for domain")

	return slv.Present(ch.Spec.DNSName, fqdn, ch.Spec.Key)
}

// Check verifies that the DNS records for the ACME challenge have propagated.
func (s *Solver) Check(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error {
	log := logf.WithResource(logf.FromContext(ctx, "Check"), ch).WithValues("domain", ch.Spec.DNSName)

	fqdn, err := util.DNS01LookupFQDN(ch.Spec.DNSName, false, s.DNS01Nameservers...)
	if err != nil {
		return err
	}

	log.V(logf.DebugLevel).Info("checking DNS propagation", "nameservers", s.Context.DNS01Nameservers)

	ok, err := util.PreCheckDNS(fqdn, ch.Spec.Key, s.Context.DNS01Nameservers,
		s.Context.DNS01CheckAuthoritative)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("DNS record for %q not yet propagated", ch.Spec.DNSName)
	}

	ttl := 60
	log.V(logf.DebugLevel).Info("waiting DNS record TTL to allow the DNS01 record to propagate for domain", "ttl", ttl, "fqdn", fqdn)
	time.Sleep(time.Second * time.Duration(ttl))
	log.V(logf.DebugLevel).Info("ACME DNS01 validation record propagated", "fqdn", fqdn)

	return nil
}

// CleanUp removes DNS records which are no longer needed after
// certificate issuance.
func (s *Solver) CleanUp(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error {
	log := logf.WithResource(logf.FromContext(ctx, "CleanUp"), ch).WithValues("domain", ch.Spec.DNSName)
	ctx = logf.NewContext(ctx, log)

	webhookSolver, req, err := s.prepareChallengeRequest(issuer, ch)
	if err != nil && err != errNotFound {
		return err
	}
	if err == nil {
		log.V(logf.DebugLevel).Info("cleaning up DNS01 challenge")
		return webhookSolver.CleanUp(req)
	}

	slv, providerConfig, err := s.solverForChallenge(ctx, issuer, ch)
	if err != nil {
		return err
	}

	fqdn, err := util.DNS01LookupFQDN(ch.Spec.DNSName, followCNAME(providerConfig.CNAMEStrategy), s.DNS01Nameservers...)
	if err != nil {
		return err
	}

	return slv.CleanUp(ch.Spec.DNSName, fqdn, ch.Spec.Key)
}

func followCNAME(strategy cmacme.CNAMEStrategy) bool {
	if strategy == cmacme.FollowStrategy {
		return true
	}
	return false
}

func extractChallengeSolverConfig(ch *cmacme.Challenge) (*cmacme.ACMEChallengeSolverDNS01, error) {
	if ch.Spec.Solver.DNS01 == nil {
		return nil, fmt.Errorf("no dns01 challenge solver configuration found")
	}

	return ch.Spec.Solver.DNS01, nil
}

// solverForChallenge returns a Solver for the given providerName.
// The providerName is the name of an ACME DNS-01 challenge provider as
// specified on the Issuer resource for the Solver.
func (s *Solver) solverForChallenge(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) (solver, *cmacme.ACMEChallengeSolverDNS01, error) {
	log := logf.FromContext(ctx, "solverForChallenge")
	dbg := log.V(logf.DebugLevel)

	resourceNamespace := s.ResourceNamespace(issuer)
	canUseAmbientCredentials := s.CanUseAmbientCredentials(issuer)

	providerConfig, err := extractChallengeSolverConfig(ch)
	if err != nil {
		return nil, nil, err
	}

	var impl solver
	switch {
	case providerConfig.Akamai != nil:
		dbg.Info("preparing to create Akamai provider")
		clientToken, err := s.loadSecretData(&providerConfig.Akamai.ClientToken, resourceNamespace)
		if err != nil {
			return nil, nil, errors.Wrap(err, "error getting akamai client token")
		}

		clientSecret, err := s.loadSecretData(&providerConfig.Akamai.ClientSecret, resourceNamespace)
		if err != nil {
			return nil, nil, errors.Wrap(err, "error getting akamai client secret")
		}

		accessToken, err := s.loadSecretData(&providerConfig.Akamai.AccessToken, resourceNamespace)
		if err != nil {
			return nil, nil, errors.Wrap(err, "error getting akamai access token")
		}

		impl, err = akamai.NewDNSProvider(
			providerConfig.Akamai.ServiceConsumerDomain,
			string(clientToken),
			string(clientSecret),
			string(accessToken),
			s.DNS01Nameservers)
		if err != nil {
			return nil, nil, errors.Wrap(err, "error instantiating akamai challenge solver")
		}
	case providerConfig.CloudDNS != nil:
		dbg.Info("preparing to create CloudDNS provider")
		var keyData []byte

		// if the serviceAccount field isn't nil we will load credentials from
		// that secret.  If it is nil we will attempt to instantiate the
		// provider using ambient credentials (if enabled).
		if providerConfig.CloudDNS.ServiceAccount != nil {
			saSecret, err := s.secretLister.Secrets(resourceNamespace).Get(providerConfig.CloudDNS.ServiceAccount.Name)
			if err != nil {
				return nil, nil, fmt.Errorf("error getting clouddns service account: %s", err)
			}

			saKey := providerConfig.CloudDNS.ServiceAccount.Key
			keyData = saSecret.Data[saKey]
			if len(keyData) == 0 {
				return nil, nil, fmt.Errorf("specified key %q not found in secret %s/%s", saKey, saSecret.Namespace, saSecret.Name)
			}
		}

		// attempt to construct the cloud dns provider
		impl, err = s.dnsProviderConstructors.cloudDNS(providerConfig.CloudDNS.Project, keyData, s.DNS01Nameservers, s.CanUseAmbientCredentials(issuer), providerConfig.CloudDNS.HostedZoneName)
		if err != nil {
			return nil, nil, fmt.Errorf("error instantiating google clouddns challenge solver: %s", err)
		}
	case providerConfig.Cloudflare != nil:
		dbg.Info("preparing to create Cloudflare provider")
		if providerConfig.Cloudflare.APIKey != nil && providerConfig.Cloudflare.APIToken != nil {
			return nil, nil, fmt.Errorf("API key and API token secret references are both present")
		}

		var saSecretName, saSecretKey string
		if providerConfig.Cloudflare.APIKey != nil {
			saSecretName = providerConfig.Cloudflare.APIKey.Name
			saSecretKey = providerConfig.Cloudflare.APIKey.Key
		} else {
			saSecretName = providerConfig.Cloudflare.APIToken.Name
			saSecretKey = providerConfig.Cloudflare.APIToken.Key
		}

		saSecret, err := s.secretLister.Secrets(resourceNamespace).Get(saSecretName)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting cloudflare secret: %s", err)
		}

		keyData, ok := saSecret.Data[saSecretKey]
		if !ok {
			return nil, nil, fmt.Errorf("specified key %q not found in secret %s/%s", saSecretKey, saSecret.Namespace, saSecret.Name)
		}

		var apiKey, apiToken string
		if providerConfig.Cloudflare.APIKey != nil {
			apiKey = string(keyData)
		} else {
			apiToken = string(keyData)
		}

		email := providerConfig.Cloudflare.Email
		impl, err = s.dnsProviderConstructors.cloudFlare(email, apiKey, apiToken, s.DNS01Nameservers)
		if err != nil {
			return nil, nil, fmt.Errorf("error instantiating cloudflare challenge solver: %s", err)
		}
	case providerConfig.Hetzner != nil:
		dbg.Info("preparing to create Hetzner provider")
		apiTokenSecret, err := s.secretLister.Secrets(resourceNamespace).Get(providerConfig.Hetzner.Token.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting hetzner token: %s", err)
		}

		apiToken := string(apiTokenSecret.Data[providerConfig.DigitalOcean.Token.Key])

		impl, err = s.dnsProviderConstructors.hetzner(strings.TrimSpace(apiToken), s.DNS01Nameservers)
		if err != nil {
			return nil, nil, fmt.Errorf("error instantiating hetzner challenge solver: %s", err.Error())
		}
	case providerConfig.DigitalOcean != nil:
		dbg.Info("preparing to create DigitalOcean provider")
		apiTokenSecret, err := s.secretLister.Secrets(resourceNamespace).Get(providerConfig.DigitalOcean.Token.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting digitalocean token: %s", err)
		}

		apiToken := string(apiTokenSecret.Data[providerConfig.DigitalOcean.Token.Key])

		impl, err = s.dnsProviderConstructors.digitalOcean(strings.TrimSpace(apiToken), s.DNS01Nameservers)
		if err != nil {
			return nil, nil, fmt.Errorf("error instantiating digitalocean challenge solver: %s", err.Error())
		}
	case providerConfig.Route53 != nil:
		dbg.Info("preparing to create Route53 provider")
		secretAccessKey := ""
		if providerConfig.Route53.SecretAccessKey.Name != "" {
			secretAccessKeySecret, err := s.secretLister.Secrets(resourceNamespace).Get(providerConfig.Route53.SecretAccessKey.Name)
			if err != nil {
				return nil, nil, fmt.Errorf("error getting route53 secret access key: %s", err)
			}

			secretAccessKeyBytes, ok := secretAccessKeySecret.Data[providerConfig.Route53.SecretAccessKey.Key]
			if !ok {
				return nil, nil, fmt.Errorf("error getting route53 secret access key: key '%s' not found in secret", providerConfig.Route53.SecretAccessKey.Key)
			}
			secretAccessKey = string(secretAccessKeyBytes)
		}

		impl, err = s.dnsProviderConstructors.route53(
			strings.TrimSpace(providerConfig.Route53.AccessKeyID),
			strings.TrimSpace(secretAccessKey),
			providerConfig.Route53.HostedZoneID,
			providerConfig.Route53.Region,
			providerConfig.Route53.Role,
			canUseAmbientCredentials,
			s.DNS01Nameservers,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("error instantiating route53 challenge solver: %s", err)
		}
	case providerConfig.AzureDNS != nil:
		dbg.Info("preparing to create AzureDNS provider")
		secret := ""
		// if ClientID is empty, then we try to use MSI (azure metadata API for credentials)
		// if ClientID is empty we don't even try to get the ClientSecret because it would not be used
		if providerConfig.AzureDNS.ClientID != "" {
			clientSecret, err := s.secretLister.Secrets(resourceNamespace).Get(providerConfig.AzureDNS.ClientSecret.Name)
			if err != nil {
				return nil, nil, fmt.Errorf("error getting azuredns client secret: %s", err)
			}

			clientSecretBytes, ok := clientSecret.Data[providerConfig.AzureDNS.ClientSecret.Key]
			if !ok {
				return nil, nil, fmt.Errorf("error getting azure dns client secret: key '%s' not found in secret", providerConfig.AzureDNS.ClientSecret.Key)
			}
			secret = string(clientSecretBytes)
		}
		impl, err = s.dnsProviderConstructors.azureDNS(
			string(providerConfig.AzureDNS.Environment),
			providerConfig.AzureDNS.ClientID,
			secret,
			providerConfig.AzureDNS.SubscriptionID,
			providerConfig.AzureDNS.TenantID,
			providerConfig.AzureDNS.ResourceGroupName,
			providerConfig.AzureDNS.HostedZoneName,
			s.DNS01Nameservers,
			canUseAmbientCredentials,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("error instantiating azuredns challenge solver: %s", err)
		}
	case providerConfig.AcmeDNS != nil:
		dbg.Info("preparing to create ACMEDNS provider")
		accountSecret, err := s.secretLister.Secrets(resourceNamespace).Get(providerConfig.AcmeDNS.AccountSecret.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting acmedns accounts secret: %s", err)
		}

		accountSecretBytes, ok := accountSecret.Data[providerConfig.AcmeDNS.AccountSecret.Key]
		if !ok {
			return nil, nil, fmt.Errorf("error getting acmedns accounts secret: key '%s' not found in secret", providerConfig.AcmeDNS.AccountSecret.Key)
		}

		impl, err = s.dnsProviderConstructors.acmeDNS(
			providerConfig.AcmeDNS.Host,
			accountSecretBytes,
			s.DNS01Nameservers,
		)
		if err != nil {
			return nil, providerConfig, fmt.Errorf("error instantiating acmedns challenge solver: %s", err)
		}
	default:
		return nil, providerConfig, fmt.Errorf("no dns provider config specified for challenge")
	}

	return impl, providerConfig, nil
}

func (s *Solver) prepareChallengeRequest(issuer v1.GenericIssuer, ch *cmacme.Challenge) (webhook.Solver, *whapi.ChallengeRequest, error) {
	dns01Config, err := extractChallengeSolverConfig(ch)
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

	req := &whapi.ChallengeRequest{
		Type:                    "dns-01",
		ResolvedFQDN:            fqdn,
		ResolvedZone:            zone,
		AllowAmbientCredentials: canUseAmbientCredentials,
		ResourceNamespace:       resourceNamespace,
		Key:                     ch.Spec.Key,
		DNSName:                 ch.Spec.DNSName,
		Config:                  &apiext.JSON{Raw: b},
	}

	return webhookSolver, req, nil
}

var errNotFound = fmt.Errorf("failed to determine DNS01 solver type")

func (s *Solver) dns01SolverForConfig(config *cmacme.ACMEChallengeSolverDNS01) (webhook.Solver, interface{}, error) {
	solverName := ""
	var c interface{}
	switch {
	case config.Webhook != nil:
		solverName = "webhook"
		c = config.Webhook
	case config.RFC2136 != nil:
		solverName = "rfc2136"
		c = config.RFC2136
	}
	if solverName == "" {
		return nil, nil, errNotFound
	}
	p := s.webhookSolvers[solverName]
	if p == nil {
		return nil, c, fmt.Errorf("no solver provider configured for %q", solverName)
	}
	return p, c, nil
}

// NewSolver creates a Solver which can instantiate the appropriate DNS
// provider.
func NewSolver(ctx *controller.Context) (*Solver, error) {
	webhookSolvers := []webhook.Solver{
		&webhookslv.Webhook{},
		rfc2136.New(rfc2136.WithNamespace(ctx.Namespace)),
	}

	initialized := make(map[string]webhook.Solver)

	// the RESTConfig may be nil if we are running in a unit test environment,
	// so don't initialize the webhook based solvers in this case.
	if ctx.RESTConfig != nil {
		// initialize all DNS providers
		for _, s := range webhookSolvers {
			err := s.Initialize(ctx.RESTConfig, ctx.StopCh)
			if err != nil {
				return nil, fmt.Errorf("error initializing DNS provider %q: %v", s.Name(), err)
			}
			initialized[s.Name()] = s
		}
	}

	return &Solver{
		Context:      ctx,
		secretLister: ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		dnsProviderConstructors: dnsProviderConstructors{
			clouddns.NewDNSProvider,
			cloudflare.NewDNSProviderCredentials,
			route53.NewDNSProvider,
			azuredns.NewDNSProviderCredentials,
			acmedns.NewDNSProviderHostBytes,
			digitalocean.NewDNSProviderCredentials,
		},
		webhookSolvers: initialized,
	}, nil
}

func (s *Solver) loadSecretData(selector *cmmeta.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := s.secretLister.Secrets(ns).Get(selector.Name)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load secret %q", ns+"/"+selector.Name)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}

	return nil, errors.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}
