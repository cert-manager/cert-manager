package dns

import (
	"context"
	"fmt"
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

type Solver struct {
	issuer            v1alpha1.GenericIssuer
	client            kubernetes.Interface
	secretLister      corev1listers.SecretLister
	resourceNamespace string
}

func (s *Solver) Present(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error {
	slv, err := s.solverFor(crt, domain)
	if err != nil {
		return err
	}
	glog.V(4).Infof("Presenting DNS01 challenge for domain %q", domain)
	return slv.Present(domain, token, key)
}

func (s *Solver) Wait(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error {
	slv, err := s.solverFor(crt, domain)
	if err != nil {
		return err
	}

	type boolErr struct {
		bool
		error
	}

	fqdn, value, ttl := util.DNS01Record(domain, key)

	glog.V(4).Infof("Checking DNS propagation for %q using name servers: %v", domain, util.RecursiveNameservers)

	timeout, interval := slv.Timeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		select {
		case r := <-func() <-chan boolErr {
			out := make(chan boolErr, 1)
			go func() {
				defer close(out)
				ok, err := util.PreCheckDNS(fqdn, value)
				out <- boolErr{ok, err}
			}()
			return out
		}():

			if r.error != nil {
				glog.Warningf("Failed to check for DNS propagation of %q: %v", domain, r.error)
			} else if r.bool {
				// TODO: move this to somewhere else
				// TODO: make this wait for whatever the record *was*, not is now
				glog.V(4).Infof("Waiting DNS record TTL (%ds) to allow propagation for propagation of DNS record for domain %q", ttl, fqdn)
				time.Sleep(time.Second * time.Duration(ttl))
				glog.V(4).Infof("ACME DNS01 validation record propagated for %q", fqdn)
				return nil
			} else {
				glog.V(4).Infof("DNS record for %q not yet propagated", domain)
			}
			time.Sleep(interval)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
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

		impl, err = clouddns.NewDNSProviderServiceAccountBytes(providerConfig.CloudDNS.Project, saBytes)
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

		impl, err = cloudflare.NewDNSProviderCredentials(email, apiKey)
		if err != nil {
			return nil, fmt.Errorf("error instantiating cloudflare challenge solver: %s", err.Error())
		}
	case providerConfig.Route53 != nil:
		secretAccessKey := ""
		if providerConfig.Route53.SecretAccessKey.Name != "" {
			secretAccessKeySecret, err := s.secretLister.Secrets(s.resourceNamespace).Get(providerConfig.Route53.SecretAccessKey.Name)
			if err != nil {
				return nil, fmt.Errorf("error getting route53 secret access key: %s", err.Error())
			}

			secretAccessKeyBytes, ok := secretAccessKeySecret.Data[providerConfig.Route53.SecretAccessKey.Key]
			if !ok {
				return nil, fmt.Errorf("error getting route53 secret access key: key '%s' not found in secret", providerConfig.Route53.SecretAccessKey.Key)
			}
			secretAccessKey = string(secretAccessKeyBytes)
		}

		impl, err = route53.NewDNSProviderAccessKey(
			providerConfig.Route53.AccessKeyID,
			secretAccessKey,
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

		impl, err = azuredns.NewDNSProviderCredentials(
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
	return &Solver{issuer, client, secretLister, resourceNamespace}
}
