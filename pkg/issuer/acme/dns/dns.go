package dns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang/glog"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"

	"github.com/pkg/errors"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/akamai"
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
	route53    func(accessKey, secretKey, hostedZoneID, region string, ambient bool) (*route53.DNSProvider, error)
	azureDNS   func(clientID, clientSecret, subscriptionID, tenentID, resourceGroupName, hostedZoneName string) (*azuredns.DNSProvider, error)
}

// Solver is a solver for the acme dns01 challenge.
// Given a Certificate object, it determines the correct DNS provider based on
// the certificate, and configures it based on the referenced issuer.
type Solver struct {
	issuer                  v1alpha1.GenericIssuer
	client                  kubernetes.Interface
	secretLister            corev1listers.SecretLister
	resourceNamespace       string
	dnsProviderConstructors dnsProviderConstructors
	ambientCredentials      bool
	dns01Nameservers        []string
}

func (s *Solver) Present(ctx context.Context, _ *v1alpha1.Certificate, ch v1alpha1.ACMEOrderChallenge) error {
	if ch.SolverConfig.DNS01 == nil {
		return fmt.Errorf("challenge dns config must be specified")
	}

	providerName := ch.SolverConfig.DNS01.Provider
	if providerName == "" {
		return fmt.Errorf("dns01 challenge provider name must be set")
	}

	slv, err := s.solverForIssuerProvider(providerName)
	if err != nil {
		return err
	}

	glog.Infof("Presenting DNS01 challenge for domain %q", ch.Domain)
	return slv.Present(ch.Domain, ch.Token, ch.Key)
}

func (s *Solver) Check(ch v1alpha1.ACMEOrderChallenge) (bool, error) {
	fqdn, value, ttl := util.DNS01Record(ch.Domain, ch.Key)
	glog.Infof("Checking DNS propagation for %q using name servers: %v", ch.Domain, s.dns01Nameservers)

	ok, err := util.PreCheckDNS(fqdn, value, s.dns01Nameservers)
	if err != nil {
		return false, err
	}
	if !ok {
		glog.Infof("DNS record for %q not yet propagated", ch.Domain)
		return false, nil
	}

	glog.Infof("Waiting DNS record TTL (%ds) to allow propagation of DNS record for domain %q", ttl, fqdn)
	time.Sleep(time.Second * time.Duration(ttl))
	glog.Infof("ACME DNS01 validation record propagated for %q", fqdn)

	return true, nil
}

func (s *Solver) CleanUp(ctx context.Context, _ *v1alpha1.Certificate, ch v1alpha1.ACMEOrderChallenge) error {
	if ch.SolverConfig.DNS01 == nil {
		return fmt.Errorf("challenge dns config must be specified")
	}

	providerName := ch.SolverConfig.DNS01.Provider
	if providerName == "" {
		return fmt.Errorf("dns01 challenge provider name must be set")
	}

	slv, err := s.solverForIssuerProvider(providerName)
	if err != nil {
		return err
	}

	return slv.CleanUp(ch.Domain, ch.Token, ch.Key)
}

// solverForIssuerProvider returns a Solver for the given providerName.
// The providerName is the name of an ACME DNS-01 challenge provider as
// specified on the Issuer resource for the Solver.
//
// This method is exported so that only the provider name is required in order
// to obtain an instance of a Solver. This is useful when cleaning up old
// challenges after the ACME challenge configuration on the Certificate has
// been removed by the user.
func (s *Solver) solverForIssuerProvider(providerName string) (solver, error) {
	providerConfig, err := s.issuer.GetSpec().ACME.DNS01.Provider(providerName)
	if err != nil {
		return nil, err
	}

	var impl solver
	switch {
	case providerConfig.Akamai != nil:
		clientToken, err := s.loadSecretData(&providerConfig.Akamai.ClientToken)
		if err != nil {
			return nil, errors.Wrap(err, "error getting akamai client token")
		}

		clientSecret, err := s.loadSecretData(&providerConfig.Akamai.ClientSecret)
		if err != nil {
			return nil, errors.Wrap(err, "error getting akamai client secret")
		}

		accessToken, err := s.loadSecretData(&providerConfig.Akamai.AccessToken)
		if err != nil {
			return nil, errors.Wrap(err, "error getting akamai access token")
		}

		impl, err = akamai.NewDNSProvider(
			providerConfig.Akamai.ServiceConsumerDomain,
			string(clientToken),
			string(clientSecret),
			string(accessToken))
		if err != nil {
			return nil, errors.Wrap(err, "error instantiating akamai challenge solver")
		}
	case providerConfig.CloudDNS != nil:
		saSecret, err := s.secretLister.Secrets(s.resourceNamespace).Get(providerConfig.CloudDNS.ServiceAccount.Name)
		if err != nil {
			return nil, fmt.Errorf("error getting clouddns service account: %s", err)
		}

		saKey := providerConfig.CloudDNS.ServiceAccount.Key
		saBytes := saSecret.Data[saKey]

		if len(saBytes) == 0 {
			return nil, fmt.Errorf("specfied key %q not found in secret %s/%s", saKey, saSecret.Namespace, saSecret.Name)
		}

		impl, err = s.dnsProviderConstructors.cloudDNS(providerConfig.CloudDNS.Project, saBytes)
		if err != nil {
			return nil, fmt.Errorf("error instantiating google clouddns challenge solver: %s", err)
		}
	case providerConfig.Cloudflare != nil:
		apiKeySecret, err := s.secretLister.Secrets(s.resourceNamespace).Get(providerConfig.Cloudflare.APIKey.Name)
		if err != nil {
			return nil, fmt.Errorf("error getting cloudflare service account: %s", err)
		}

		email := providerConfig.Cloudflare.Email
		apiKey := string(apiKeySecret.Data[providerConfig.Cloudflare.APIKey.Key])

		impl, err = s.dnsProviderConstructors.cloudFlare(email, apiKey)
		if err != nil {
			return nil, fmt.Errorf("error instantiating cloudflare challenge solver: %s", err)
		}
	case providerConfig.Route53 != nil:
		secretAccessKey := ""
		if providerConfig.Route53.SecretAccessKey.Name != "" {
			secretAccessKeySecret, err := s.secretLister.Secrets(s.resourceNamespace).Get(providerConfig.Route53.SecretAccessKey.Name)
			if err != nil {
				return nil, fmt.Errorf("error getting route53 secret access key: %s", err)
			}

			secretAccessKeyBytes, ok := secretAccessKeySecret.Data[providerConfig.Route53.SecretAccessKey.Key]
			if !ok {
				return nil, fmt.Errorf("error getting route53 secret access key: key '%s' not found in secret", providerConfig.Route53.SecretAccessKey.Key)
			}
			secretAccessKey = string(secretAccessKeyBytes)
		}

		impl, err = s.dnsProviderConstructors.route53(
			strings.TrimSpace(providerConfig.Route53.AccessKeyID),
			strings.TrimSpace(secretAccessKey),
			providerConfig.Route53.HostedZoneID,
			providerConfig.Route53.Region,
			s.ambientCredentials,
		)
		if err != nil {
			return nil, fmt.Errorf("error instantiating route53 challenge solver: %s", err)
		}
	case providerConfig.AzureDNS != nil:
		clientSecret, err := s.secretLister.Secrets(s.resourceNamespace).Get(providerConfig.AzureDNS.ClientSecret.Name)
		if err != nil {
			return nil, fmt.Errorf("error getting azuredns client secret: %s", err)
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
		return nil, fmt.Errorf("no dns provider config specified for provider %q", providerName)
	}

	return impl, nil
}

func NewSolver(issuer v1alpha1.GenericIssuer, client kubernetes.Interface, secretLister corev1listers.SecretLister, resourceNamespace string, ambientCredentials bool, dns01Nameservers []string) *Solver {
	return &Solver{
		issuer,
		client,
		secretLister,
		resourceNamespace,
		dnsProviderConstructors{
			clouddns.NewDNSProviderServiceAccountBytes,
			cloudflare.NewDNSProviderCredentials,
			route53.NewDNSProvider,
			azuredns.NewDNSProviderCredentials,
		},
		ambientCredentials,
		dns01Nameservers,
	}
}

func (s *Solver) loadSecretData(selector *v1alpha1.SecretKeySelector) ([]byte, error) {
	secret, err := s.secretLister.Secrets(s.resourceNamespace).Get(selector.Name)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load secret %q", s.resourceNamespace+"/"+selector.Name)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}

	return nil, errors.Errorf("no key %q in secret %q", selector.Key, s.resourceNamespace+"/"+selector.Name)
}
