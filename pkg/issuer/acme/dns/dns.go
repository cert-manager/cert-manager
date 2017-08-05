package dns

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"

	"github.com/munnerz/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/munnerz/cert-manager/pkg/issuer/acme/dns/clouddns"
)

const (
	cloudDNSServiceAccountKey = "service-account.json"
)

type solver interface {
	Present(domain, token, key string) error
	CleanUp(domain, token, key string) error
}

type Solver struct {
	issuer       *v1alpha1.Issuer
	client       kubernetes.Interface
	secretLister corev1listers.SecretLister
}

func (s *Solver) Present(crt *v1alpha1.Certificate, domain, token, key string) error {
	slv, err := s.solverFor(crt, domain)
	if err != nil {
		return err
	}
	return slv.Present(domain, token, key)
}

func (s *Solver) CleanUp(crt *v1alpha1.Certificate, domain, token, key string) error {
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
		if providerConfig.CloudDNS.ServiceAccount == "" {
			impl, err = clouddns.NewDNSProviderCredentials(providerConfig.CloudDNS.Project)

			if err != nil {
				return nil, fmt.Errorf("error instantiating google clouddns challenge solver: %s", err.Error())
			}

			break
		}

		saSecret, err := s.secretLister.Secrets(s.issuer.Namespace).Get(providerConfig.CloudDNS.ServiceAccount)
		if err != nil {
			return nil, fmt.Errorf("error getting clouddns service account: %s", err.Error())
		}
		saBytes := saSecret.Data[cloudDNSServiceAccountKey]

		impl, err = clouddns.NewDNSProviderServiceAccountBytes(providerConfig.CloudDNS.Project, saBytes)
		if err != nil {
			return nil, fmt.Errorf("error instantiating google clouddns challenge solver: %s", err.Error())
		}
	default:
		return nil, fmt.Errorf("no dns provider config specified for domain '%s'", domain)
	}

	return impl, nil
}

func NewSolver(issuer *v1alpha1.Issuer, client kubernetes.Interface, secretLister corev1listers.SecretLister) *Solver {
	return &Solver{issuer, client, secretLister}
}
