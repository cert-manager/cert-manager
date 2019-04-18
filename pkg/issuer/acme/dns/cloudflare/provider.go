package cloudflare

import (
	"encoding/json"
	"fmt"
	"k8s.io/client-go/listers/core/v1"
	"time"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"

	whapi "github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

type Solver struct {
	secretLister v1.SecretLister
}

func (s *Solver) Name() string {
	return "cloudflare"
}

func (s *Solver) Present(ch *whapi.ChallengeRequest) error {
	p, err := s.buildDNSProvider(ch)
	if err != nil {
		return err
	}

	err = p.Present(ch.DNSName, ch.ResolvedFQDN, ch.ResolvedZone, ch.Key)
	if err != nil {
		return err
	}

	return nil
}

func (s *Solver) CleanUp(ch *whapi.ChallengeRequest) error {
	p, err := s.buildDNSProvider(ch)
	if err != nil {
		return err
	}

	err = p.CleanUp(ch.DNSName, ch.ResolvedFQDN, ch.ResolvedZone, ch.Key)
	if err != nil {
		return err
	}

	return nil
}

func (s *Solver) Initialize(kubeClientConfig *restclient.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	// obtain a secret lister and start the informer factory to populate the
	// secret cache
	factory := informers.NewSharedInformerFactory(cl, time.Minute*5)
	s.secretLister = factory.Core().V1().Secrets().Lister()
	factory.Start(stopCh)
	factory.WaitForCacheSync(stopCh)

	return nil
}

func (s *Solver) loadConfig(cfgJSON extapi.JSON) (*cmapi.ACMEIssuerDNS01ProviderCloudflare, error) {
	cfg := cmapi.ACMEIssuerDNS01ProviderCloudflare{}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return nil, fmt.Errorf("error decoding solver config: %v", err)
	}

	return &cfg, nil
}

func (s *Solver) loadAPIKey(ch *whapi.ChallengeRequest, cfg *cmapi.ACMEIssuerDNS01ProviderCloudflare) (string, error) {
	secret, err := s.secretLister.Secrets(ch.ResourceNamespace).Get(cfg.APIKey.Name)
	if err != nil {
		return "", err
	}
	apiKeyData, ok := secret.Data[cfg.APIKey.Key]
	if !ok {
		return "", fmt.Errorf("no data for key %q found in secret '%s/%s'", cfg.APIKey.Key, ch.ResourceNamespace, cfg.APIKey.Name)
	}
	return string(apiKeyData), nil
}

func (s *Solver) buildDNSProvider(ch *whapi.ChallengeRequest) (*DNSProvider, error) {
	if ch.Config == nil {
		return nil, fmt.Errorf("no challenge solver config provided")
	}

	cfg, err := s.loadConfig(*ch.Config)
	if err != nil {
		return nil, err
	}

	apiKey, err := s.loadAPIKey(ch, cfg)
	if err != nil {
		return nil, err
	}

	p, err := NewDNSProviderCredentials(cfg.Email, apiKey)
	if err != nil {
		return nil, fmt.Errorf("error initializing DNS provider: %v", err)
	}

	return p, nil
}
