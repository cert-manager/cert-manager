package dns

import (
	"context"
	"fmt"
	"log"
	"time"

	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer/acme/dns/clouddns"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer/acme/dns/cloudflare"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer/acme/dns/route53"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer/acme/dns/util"
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
	issuer       *v1alpha1.Issuer
	client       kubernetes.Interface
	secretLister corev1listers.SecretLister
}

func (s *Solver) Present(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error {
	slv, err := s.solverFor(crt, domain)
	if err != nil {
		return err
	}
	log.Printf("presenting key: %s", key)
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

	log.Printf("[%s] Checking DNS record propagation using %+v", domain, util.RecursiveNameservers)

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
			if r.bool {
				// TODO: move this to somewhere else
				// TODO: make this wait for whatever the record *was*, not is now
				log.Printf("sleeping for dns record for '%s' ttl %ds before returning from Wait", fqdn, ttl)
				time.Sleep(time.Second * time.Duration(ttl))
				return nil
			}
			log.Printf("[%s] dns record not yet propegated", domain)
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
		s.issuer.Spec.ACME == nil ||
		s.issuer.Spec.ACME.DNS01 == nil {
		return nil, fmt.Errorf("no dns01 config found for domain '%s'", domain)
	}

	providerConfig, err := s.issuer.Spec.ACME.DNS01.Provider(cfg.Provider)
	if err != nil {
		return nil, fmt.Errorf("invalid provider config specified for domain '%s': %s", domain, err.Error())
	}

	var impl solver
	switch {
	case providerConfig.CloudDNS != nil:
		saSecret, err := s.secretLister.Secrets(s.issuer.Namespace).Get(providerConfig.CloudDNS.ServiceAccount.Name)
		if err != nil {
			return nil, fmt.Errorf("error getting clouddns service account: %s", err.Error())
		}
		saBytes := saSecret.Data[providerConfig.CloudDNS.ServiceAccount.Key]

		impl, err = clouddns.NewDNSProviderServiceAccountBytes(providerConfig.CloudDNS.Project, saBytes)
		if err != nil {
			return nil, fmt.Errorf("error instantiating google clouddns challenge solver: %s", err.Error())
		}
	case providerConfig.Cloudflare != nil:
		apiKeySecret, err := s.secretLister.Secrets(s.issuer.Namespace).Get(providerConfig.Cloudflare.APIKey.Name)
		if err != nil {
			return nil, fmt.Errorf("error getting clouddns service account: %s", err.Error())
		}

		email := providerConfig.Cloudflare.Email
		apiKey := string(apiKeySecret.Data[providerConfig.Cloudflare.APIKey.Key])

		impl, err = cloudflare.NewDNSProviderCredentials(email, apiKey)
		if err != nil {
			return nil, fmt.Errorf("error instantiating cloudflare challenge solver: %s", err.Error())
		}
	case providerConfig.Route53 != nil:
		secretAccessKeySecret, err := s.secretLister.Secrets(s.issuer.Namespace).Get(providerConfig.Route53.SecretAccessKey.Name)
		if err != nil {
			return nil, fmt.Errorf("error getting route53 secret access key: %s", err.Error())
		}

		secretAccessKeyBytes, ok := secretAccessKeySecret.Data[providerConfig.Cloudflare.APIKey.Key]
		if !ok {
			return nil, fmt.Errorf("error getting route53 secret access key: key '%s' not found in secret", providerConfig.Route53.SecretAccessKey.Key)
		}

		impl, err = route53.NewDNSProviderAccessKey(
			providerConfig.Route53.AccessKeyID,
			string(secretAccessKeyBytes),
			providerConfig.Route53.HostedZoneID,
			providerConfig.Route53.Region,
		)
		if err != nil {
			return nil, fmt.Errorf("error instantiating route53 challenge solver: %s", err.Error())
		}
	default:
		return nil, fmt.Errorf("no dns provider config specified for domain '%s'", domain)
	}

	return impl, nil
}

func NewSolver(issuer *v1alpha1.Issuer, client kubernetes.Interface, secretLister corev1listers.SecretLister) *Solver {
	return &Solver{issuer, client, secretLister}
}
