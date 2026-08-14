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
	"errors"
	"fmt"
	"strings"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/acmedns"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/akamai"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/azuredns"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/clouddns"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/cloudflare"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/digitalocean"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/rfc2136"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/route53"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	webhookslv "github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/webhook"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// solver is the old solver type interface.
// All new solvers should be implemented using the new webhook.Solver interface.
type solver interface {
	Present(ctx context.Context, domain, fqdn, value string) error
	CleanUp(ctx context.Context, domain, fqdn, value string) error
}

// dnsProviderConstructors defines how each provider may be constructed.
// It is useful for mocking out a given provider since an alternate set of
// constructors may be set.
type dnsProviderConstructors struct {
	akamai       func(context.Context, ...akamai.DNSProviderOption) (*akamai.DNSProvider, error)
	cloudDNS     func(context.Context, ...clouddns.DNSProviderOption) (*clouddns.DNSProvider, error)
	cloudFlare   func(context.Context, ...cloudflare.DNSProviderOption) (*cloudflare.DNSProvider, error)
	route53      func(context.Context, ...route53.DNSProviderOption) (*route53.DNSProvider, error)
	azureDNS     func(context.Context, ...azuredns.DNSProviderOption) (*azuredns.DNSProvider, error)
	acmeDNS      func(context.Context, ...acmedns.DNSProviderOption) (*acmedns.DNSProvider, error)
	digitalOcean func(context.Context, ...digitalocean.DNSProviderOption) (*digitalocean.DNSProvider, error)
}

// Solver is a solver for the acme dns01 challenge.
// Given a Certificate object, it determines the correct DNS provider based on
// the certificate, and configures it based on the referenced issuer.
type Solver struct {
	*controller.Context
	secretLister            internalinformers.SecretLister
	dnsProviderConstructors dnsProviderConstructors
	webhookSolvers          map[string]webhook.Solver
}

// Present performs the work to configure DNS to resolve a DNS01 challenge.
func (s *Solver) Present(ctx context.Context, _ v1.GenericIssuer, ch *cmacme.Challenge) error {
	log := logf.WithResource(logf.FromContext(ctx, "Present"), ch).WithValues("domain", ch.Spec.DNSName)
	ctx = logf.NewContext(ctx, log)

	webhookSolver, req, err := s.prepareChallengeRequest(ctx, ch)
	if err != nil && !errors.Is(err, errNotFound) {
		return err
	}
	if err == nil {
		log.V(logf.InfoLevel).Info("presenting DNS01 challenge for domain")
		return webhookSolver.Present(req)
	}

	slv, providerConfig, err := s.solverForChallenge(ctx, ch)
	if err != nil {
		return err
	}

	nameservers, _ := s.nameserversForProviderConfig(providerConfig)

	fqdn, err := util.DNS01LookupFQDN(ctx, ch.Spec.DNSName, followCNAME(providerConfig.CNAMEStrategy), nameservers...)
	if err != nil {
		return err
	}

	log.V(logf.DebugLevel).Info("presenting DNS01 challenge for domain")

	return slv.Present(ctx, ch.Spec.DNSName, fqdn, ch.Spec.Key)
}

// Check verifies that the DNS records for the ACME challenge have propagated.
func (s *Solver) Check(ctx context.Context, issuer v1.GenericIssuer, ch *cmacme.Challenge) error {
	log := logf.WithResource(logf.FromContext(ctx, "Check"), ch).WithValues("domain", ch.Spec.DNSName)

	providerConfig, err := extractChallengeSolverConfig(ch)
	if err != nil {
		return err
	}

	nameservers, checkAuthoritative := s.nameserversForProviderConfig(providerConfig)

	fqdn, err := util.DNS01LookupFQDN(ctx, ch.Spec.DNSName, false, nameservers...)
	if err != nil {
		return err
	}

	log.V(logf.DebugLevel).Info("checking DNS propagation", "nameservers", nameservers)

	ok, err := s.DNSResolver.CheckTXTRecordPropagation(ctx, fqdn, ch.Spec.Key, nameservers,
		util.UseAuthoritative(checkAuthoritative))
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
func (s *Solver) CleanUp(ctx context.Context, ch *cmacme.Challenge) error {
	log := logf.WithResource(logf.FromContext(ctx, "CleanUp"), ch).WithValues("domain", ch.Spec.DNSName)
	ctx = logf.NewContext(ctx, log)

	webhookSolver, req, err := s.prepareChallengeRequest(ctx, ch)
	if err != nil && err != errNotFound {
		return err
	}
	if err == nil {
		log.V(logf.DebugLevel).Info("cleaning up DNS01 challenge")
		return webhookSolver.CleanUp(req)
	}

	slv, providerConfig, err := s.solverForChallenge(ctx, ch)
	if err != nil {
		return err
	}

	nameservers, _ := s.nameserversForProviderConfig(providerConfig)

	fqdn, err := util.DNS01LookupFQDN(ctx, ch.Spec.DNSName, followCNAME(providerConfig.CNAMEStrategy), nameservers...)
	if err != nil {
		return err
	}

	return slv.CleanUp(ctx, ch.Spec.DNSName, fqdn, ch.Spec.Key)
}

func followCNAME(strategy cmacme.CNAMEStrategy) bool {
	return strategy == cmacme.FollowStrategy
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
func (s *Solver) solverForChallenge(ctx context.Context, ch *cmacme.Challenge) (solver, *cmacme.ACMEChallengeSolverDNS01, error) {
	log := logf.FromContext(ctx, "solverForChallenge")
	dbg := log.V(logf.DebugLevel)

	resourceNamespace := s.ResourceNamespaceRef(ch.Spec.IssuerRef, ch.Namespace)
	canUseAmbientCredentials := s.CanUseAmbientCredentialsFromRef(ch.Spec.IssuerRef)

	providerConfig, err := extractChallengeSolverConfig(ch)
	if err != nil {
		return nil, nil, err
	}

	nameservers, _ := s.nameserversForProviderConfig(providerConfig)

	var impl solver
	switch {
	case providerConfig.Akamai != nil:
		dbg.Info("preparing to create Akamai provider")
		clientToken, err := s.loadSecretData(&providerConfig.Akamai.ClientToken, resourceNamespace)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting akamai client token: %w", err)
		}

		clientSecret, err := s.loadSecretData(&providerConfig.Akamai.ClientSecret, resourceNamespace)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting akamai client secret: %w", err)
		}

		accessToken, err := s.loadSecretData(&providerConfig.Akamai.AccessToken, resourceNamespace)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting akamai client token: %w", err)
		}

		impl, err = s.dnsProviderConstructors.akamai(ctx,
			akamai.ServiceConsumerDomain(providerConfig.Akamai.ServiceConsumerDomain),
			akamai.ClientToken(clientToken),
			akamai.ClientSecret(clientSecret),
			akamai.AccessToken(accessToken),
			akamai.Nameservers(nameservers),
			akamai.Resolver(s.DNSResolver))

		if err != nil {
			return nil, nil, fmt.Errorf("error instantiating akamai challenge solver: %w", err)
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
		impl, err = s.dnsProviderConstructors.cloudDNS(ctx,
			clouddns.Project(providerConfig.CloudDNS.Project),
			clouddns.ServiceAccountBytes(keyData),
			clouddns.Nameservers(nameservers),
			clouddns.Ambient(s.CanUseAmbientCredentialsFromRef(ch.Spec.IssuerRef)),
			clouddns.HostedZoneName(providerConfig.CloudDNS.HostedZoneName),
			clouddns.Resolver(s.DNSResolver))

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
		impl, err = s.dnsProviderConstructors.cloudFlare(ctx,
			cloudflare.Email(email),
			cloudflare.APIKey(apiKey),
			cloudflare.APIToken(apiToken),
			cloudflare.UserAgent(s.RESTConfig.UserAgent))
		if err != nil {
			return nil, nil, fmt.Errorf("error instantiating cloudflare challenge solver: %s", err)
		}
	case providerConfig.DigitalOcean != nil:
		dbg.Info("preparing to create DigitalOcean provider")
		apiTokenSecret, err := s.secretLister.Secrets(resourceNamespace).Get(providerConfig.DigitalOcean.Token.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting digitalocean token: %s", err)
		}

		apiToken := strings.TrimSpace(string(apiTokenSecret.Data[providerConfig.DigitalOcean.Token.Key]))

		impl, err = s.dnsProviderConstructors.digitalOcean(ctx,
			digitalocean.Token(apiToken),
			digitalocean.Nameservers(nameservers),
			digitalocean.UserAgent(s.RESTConfig.UserAgent),
			digitalocean.Resolver(s.DNSResolver))

		if err != nil {
			return nil, nil, fmt.Errorf("error instantiating digitalocean challenge solver: %s", err.Error())
		}
	case providerConfig.Route53 != nil:
		dbg.Info("preparing to create Route53 provider")

		// Default to the AccessKeyID literal in the configuration
		secretAccessKeyID := strings.TrimSpace(providerConfig.Route53.AccessKeyID)

		// If the AccessKeyID secret reference option is defined, override the
		// secretAccessKeyID variable.
		if providerConfig.Route53.SecretAccessKeyID != nil {
			// For route53, you must specify either an AccessKeyID or a secret
			// reference to an AccessKeyID, but not both.
			if len(providerConfig.Route53.AccessKeyID) > 0 {
				return nil, nil, fmt.Errorf("route53 accessKeyID and accessKeyIDSecretRef cannot both be specified")
			}

			// Ensure Key specified.
			if len(providerConfig.Route53.SecretAccessKeyID.Key) == 0 {
				return nil, nil, fmt.Errorf("route53 accessKeyIDSecretRef requires a key field to be specified")
			}

			// Ensure Name specified.
			if len(providerConfig.Route53.SecretAccessKeyID.Name) == 0 {
				return nil, nil, fmt.Errorf("route53 accessKeyIDSecretRef requires a name field to be specified")
			}

			secretAccessKeyIDSecret, err := s.secretLister.Secrets(resourceNamespace).Get(providerConfig.Route53.SecretAccessKeyID.Name)
			if err != nil {
				return nil, nil, fmt.Errorf("error getting route53 secret access key id: %s", err)
			}

			secretAccessKeyIDBytes, ok := secretAccessKeyIDSecret.Data[providerConfig.Route53.SecretAccessKeyID.Key]
			if !ok {
				return nil, nil, fmt.Errorf("no data found in Secret %q at Key %q",
					providerConfig.Route53.SecretAccessKeyID.Name,
					providerConfig.Route53.SecretAccessKeyID.Key,
				)
			}
			secretAccessKeyID = string(secretAccessKeyIDBytes)
		}

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

		webIdentityToken := ""
		if providerConfig.Route53.Auth != nil && providerConfig.Route53.Auth.Kubernetes != nil && providerConfig.Route53.Auth.Kubernetes.ServiceAccountRef != nil {
			if providerConfig.Route53.Auth.Kubernetes.ServiceAccountRef.Name == "" {
				return nil, nil, fmt.Errorf("service account name is required for Kubernetes auth")
			}

			audiences := []string{"sts.amazonaws.com"}
			if len(providerConfig.Route53.Auth.Kubernetes.ServiceAccountRef.TokenAudiences) != 0 {
				audiences = providerConfig.Route53.Auth.Kubernetes.ServiceAccountRef.TokenAudiences
			}

			jwt, err := s.createToken(ctx, resourceNamespace, providerConfig.Route53.Auth.Kubernetes.ServiceAccountRef.Name, audiences)
			if err != nil {
				return nil, nil, fmt.Errorf("error getting service account token: %w", err)
			}

			webIdentityToken = jwt
		}

		impl, err = s.dnsProviderConstructors.route53(ctx,
			route53.AccessKeyID(secretAccessKeyID),
			route53.SecretAccessKey(strings.TrimSpace(secretAccessKey)),
			route53.HostedZoneID(providerConfig.Route53.HostedZoneID),
			route53.Region(providerConfig.Route53.Region),
			route53.Role(providerConfig.Route53.Role),
			route53.WebIdentityToken(webIdentityToken),
			route53.Ambient(canUseAmbientCredentials),
			route53.Nameservers(nameservers),
			route53.UserAgent(s.RESTConfig.UserAgent),
			route53.Resolver(s.DNSResolver))

		if err != nil {
			return nil, nil, fmt.Errorf("error instantiating route53 challenge solver: %w", err)
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

		impl, err = s.dnsProviderConstructors.azureDNS(ctx,
			azuredns.Environment(providerConfig.AzureDNS.Environment),
			azuredns.ClientID(providerConfig.AzureDNS.ClientID),
			azuredns.ClientSecret(secret),
			azuredns.SubscriptionID(providerConfig.AzureDNS.SubscriptionID),
			azuredns.TenantID(providerConfig.AzureDNS.TenantID),
			azuredns.ResourceGroupName(providerConfig.AzureDNS.ResourceGroupName),
			azuredns.ZoneName(providerConfig.AzureDNS.HostedZoneName),
			azuredns.Nameservers(nameservers),
			azuredns.Ambient(canUseAmbientCredentials),
			azuredns.ManagedIdentity(providerConfig.AzureDNS.ManagedIdentity),
			azuredns.ZoneType(providerConfig.AzureDNS.ZoneType),
			azuredns.Resolver(s.DNSResolver))

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

		impl, err = s.dnsProviderConstructors.acmeDNS(ctx,
			acmedns.Host(providerConfig.AcmeDNS.Host),
			acmedns.AccountJSON(accountSecretBytes))

		if err != nil {
			return nil, providerConfig, fmt.Errorf("error instantiating acmedns challenge solver: %s", err)
		}
	default:
		return nil, providerConfig, fmt.Errorf("no dns provider config specified for challenge")
	}

	return impl, providerConfig, nil
}

func (s *Solver) prepareChallengeRequest(ctx context.Context, ch *cmacme.Challenge) (webhook.Solver, *whapi.ChallengeRequest, error) {
	dns01Config, err := extractChallengeSolverConfig(ch)
	if err != nil {
		return nil, nil, err
	}

	webhookSolver, cfg, err := s.dns01SolverForConfig(dns01Config)
	if err != nil {
		return nil, nil, err
	}

	nameservers, _ := s.nameserversForProviderConfig(dns01Config)

	fqdn, err := util.DNS01LookupFQDN(ctx, ch.Spec.DNSName, followCNAME(dns01Config.CNAMEStrategy), nameservers...)
	if err != nil {
		return nil, nil, err
	}

	zone, err := s.DNSResolver.FindZoneByFQDN(ctx, fqdn, nameservers)
	if err != nil {
		return nil, nil, err
	}

	resourceNamespace := s.ResourceNamespaceRef(ch.Spec.IssuerRef, ch.Namespace)
	canUseAmbientCredentials := s.CanUseAmbientCredentialsFromRef(ch.Spec.IssuerRef)

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
		Config:                  &apiextensionsv1.JSON{Raw: b},
	}

	return webhookSolver, req, nil
}

var errNotFound = fmt.Errorf("failed to determine DNS01 solver type")

func (s *Solver) dns01SolverForConfig(config *cmacme.ACMEChallengeSolverDNS01) (webhook.Solver, any, error) {
	solverName := ""
	var c any
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
	secretsLister := ctx.KubeSharedInformerFactory.Secrets().Lister()
	webhookSolvers := []webhook.Solver{
		&webhookslv.Webhook{},
		rfc2136.New(rfc2136.WithNamespace(ctx.Namespace), rfc2136.WithSecretsLister(secretsLister)),
	}

	initialized := make(map[string]webhook.Solver)

	// the RESTConfig may be nil if we are running in a unit test environment,
	// so don't initialize the webhook based solvers in this case.
	if ctx.RESTConfig != nil {
		// initialize all DNS providers
		for _, s := range webhookSolvers {
			err := s.Initialize(ctx.RESTConfig, ctx.RootContext.Done())
			if err != nil {
				return nil, fmt.Errorf("error initializing DNS provider %q: %v", s.Name(), err)
			}
			initialized[s.Name()] = s
		}
	}

	return &Solver{
		Context:      ctx,
		secretLister: ctx.KubeSharedInformerFactory.Secrets().Lister(),
		dnsProviderConstructors: dnsProviderConstructors{
			akamai.NewDNSProviderFromOptions,
			clouddns.NewDNSProviderFromOptions,
			cloudflare.NewDNSProviderFromOptions,
			route53.NewDNSProviderFromOptions,
			azuredns.NewDNSProviderFromOptions,
			acmedns.NewDNSProviderFromOptions,
			digitalocean.NewDNSProviderFromOptions,
		},
		webhookSolvers: initialized,
	}, nil
}

func (s *Solver) loadSecretData(selector *cmmeta.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := s.secretLister.Secrets(ns).Get(selector.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to load secret %q: %w", ns+"/"+selector.Name, err)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}

	return nil, fmt.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}

func (s *Solver) createToken(ctx context.Context, ns, serviceAccount string, audiences []string) (string, error) {
	tokenrequest, err := s.Client.CoreV1().ServiceAccounts(ns).CreateToken(ctx, serviceAccount, &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences:         audiences,
			ExpirationSeconds: new(int64(600)),
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to request token for %s/%s: %w", ns, serviceAccount, err)
	}

	return tokenrequest.Status.Token, nil
}

func (s *Solver) nameserversForProviderConfig(providerConfig *cmacme.ACMEChallengeSolverDNS01) (nameservers []string, checkAuthoritative bool) {
	if len(providerConfig.Nameservers) == 0 {
		return s.DNS01Nameservers, s.DNS01CheckAuthoritative
	}

	return providerConfig.Nameservers, false
}
