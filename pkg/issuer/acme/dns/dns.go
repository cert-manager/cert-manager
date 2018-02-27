package dns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang/glog"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/azuredns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/clouddns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/cloudflare"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/route53"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

const (
	cloudDNSServiceAccountKey = "service-account.json"
)

type solver interface {
	Present(domain, token, key string) error
	CleanUp(domain, token, key string) error
	Timeout() (timeout, interval time.Duration)
}

// dnsProviderConstructors defines how each provider may be constructed.
// It is useful for mocking out a given provider since an alternate set of
// constructors may be set.
type dnsProviderConstructors struct {
	cloudDNS   func(project string, serviceAccount []byte) (*clouddns.DNSProvider, error)
	cloudFlare func(email, apikey string) (*cloudflare.DNSProvider, error)
	route53    func(accessKey, secretKey, hostedZoneID, region string) (*route53.DNSProvider, error)
	azureDNS   func(clientID, clientSecret, subscriptionID, tenentID, resourceGroupName, hostedZoneName string) (*azuredns.DNSProvider, error)
}

// Solver is a solver for the acme dns01 challenge.
// Given a Certificate object, it determines the correct DNS provider based on
// the certificate, and configures it based on the referenced issuer.
type Solver struct {
	issuer                  v1alpha1.GenericIssuer
	client                  kubernetes.Interface
	secretLister            corev1listers.SecretLister
	dnsProviderConstructors dnsProviderConstructors
	resourceNamespace       string
}

func (s *Solver) Present(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error {
	slv, err := s.solverFor(crt, domain)
	if err != nil {
		return err
	}
	glog.Infof("Presenting DNS01 challenge for domain %q", domain)
	return slv.Present(domain, token, key)
}

func (s *Solver) Check(domain, token, key string) (bool, error) {
	fqdn, value, ttl := util.DNS01Record(domain, key)
	glog.Infof("Checking DNS propagation for %q using name servers: %v", domain, util.RecursiveNameservers)

	ok, err := util.PreCheckDNS(fqdn, value)
	if err != nil {
		return false, err
	}

	if ok {
		glog.Infof("Waiting DNS record TTL (%ds) to allow propagation for propagation of DNS record for domain %q", ttl, fqdn)
		time.Sleep(time.Second * time.Duration(ttl))
		glog.Infof("ACME DNS01 validation record propagated for %q", fqdn)
		return true, nil
	}

	glog.Infof("DNS record for %q not yet propagated", domain)
	return false, nil
}

func (s *Solver) CleanUp(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error {
	slv, err := s.solverFor(crt, domain)
	if err != nil {
		return err
	}
	return slv.CleanUp(domain, token, key)
}

func (s *Solver) solverFor(crt *v1alpha1.Certificate, domain string) (solver, error) {
	var cfg *v1alpha1.ACMECertificateDNS01Config
	if cfg = crt.Spec.ACME.ConfigForDomain(domain).DNS01; cfg == nil ||
		cfg.Provider == "" ||
		s.issuer.GetSpec().ACME == nil ||
		s.issuer.GetSpec().ACME.DNS01 == nil {
		return nil, fmt.Errorf("no dns01 config found for domain '%s'", domain)
	}

	providerConfig, err := s.issuer.GetSpec().ACME.DNS01.Provider(cfg.Provider)
	if err != nil {
		return nil, fmt.Errorf("invalid provider config specified for domain '%s': %s", domain, err.Error())
	}

	var impl solver
	switch {
	case providerConfig.CloudDNS != nil:
		saSecret, err := s.secretLister.Secrets(s.resourceNamespace).Get(providerConfig.CloudDNS.ServiceAccount.Name)
		if err != nil {
			return nil, fmt.Errorf("error getting clouddns service account: %s", err.Error())
		}
		saBytes := saSecret.Data[providerConfig.CloudDNS.ServiceAccount.Key]

		impl, err = s.dnsProviderConstructors.cloudDNS(providerConfig.CloudDNS.Project, saBytes)
		if err != nil {
			return nil, fmt.Errorf("error instantiating google clouddns challenge solver: %s", err.Error())
		}
	case providerConfig.Cloudflare != nil:
		apiKeySecret, err := s.secretLister.Secrets(s.resourceNamespace).Get(providerConfig.Cloudflare.APIKey.Name)
		if err != nil {
			return nil, fmt.Errorf("error getting cloudflare service account: %s", err.Error())
		}

		email := providerConfig.Cloudflare.Email
		apiKey := string(apiKeySecret.Data[providerConfig.Cloudflare.APIKey.Key])

		impl, err = s.dnsProviderConstructors.cloudFlare(email, apiKey)
		if err != nil {
			return nil, fmt.Errorf("error instantiating cloudflare challenge solver: %s", err.Error())
		}
	case providerConfig.Route53 != nil:
		secretAccessKeySecret, err := s.secretLister.Secrets(s.resourceNamespace).Get(providerConfig.Route53.SecretAccessKey.Name)
		if err != nil {
			return nil, fmt.Errorf("error getting route53 secret access key: %s", err.Error())
		}

		secretAccessKeyBytes, ok := secretAccessKeySecret.Data[providerConfig.Route53.SecretAccessKey.Key]
		if !ok {
			return nil, fmt.Errorf("error getting route53 secret access key: key '%s' not found in secret", providerConfig.Route53.SecretAccessKey.Key)
		}

		impl, err = s.dnsProviderConstructors.route53(
			strings.TrimSpace(providerConfig.Route53.AccessKeyID),
			strings.TrimSpace(string(secretAccessKeyBytes)),
			providerConfig.Route53.HostedZoneID,
			providerConfig.Route53.Region,
		)
		if err != nil {
			return nil, fmt.Errorf("error instantiating route53 challenge solver: %s", err.Error())
		}
	case providerConfig.AzureDNS != nil:
		clientSecret, err := s.secretLister.Secrets(s.resourceNamespace).Get(providerConfig.AzureDNS.ClientSecret.Name)
		if err != nil {
			return nil, fmt.Errorf("error getting azuredns client secret: %s", err.Error())
		}

		clientSecretBytes, ok := clientSecret.Data[providerConfig.AzureDNS.ClientSecret.Key]
		if !ok {
			return nil, fmt.Errorf("error getting azure dns client secret: key '%s' not found in secret", providerConfig.AzureDNS.ClientSecret.Key)
		}

		impl, err = s.dnsProviderConstructors.azureDNS(
			providerConfig.AzureDNS.ClientID,
			string(clientSecretBytes),
			providerConfig.AzureDNS.SubscriptionID,
			providerConfig.AzureDNS.TenantID,
			providerConfig.AzureDNS.ResourceGroupName,
			providerConfig.AzureDNS.HostedZoneName,
		)
	default:
		return nil, fmt.Errorf("no dns provider config specified for domain '%s'", domain)
	}

	return impl, nil
}

func NewSolver(issuer v1alpha1.GenericIssuer, client kubernetes.Interface, secretLister corev1listers.SecretLister, resourceNamespace string) *Solver {
	return &Solver{
		issuer,
		client,
		secretLister,
		dnsProviderConstructors{
			clouddns.NewDNSProviderServiceAccountBytes,
			cloudflare.NewDNSProviderCredentials,
			route53.NewDNSProviderAccessKey,
			azuredns.NewDNSProviderCredentials,
		},
		resourceNamespace,
	}
}
