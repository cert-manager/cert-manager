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

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

type Solver struct {
	secretLister v1.SecretLister
}

type config struct {
	Email           string `json:"email"`
	APIKeySecretRef cmapi.SecretKeySelector
}

func (s *Solver) Name() string {
	return "cloudflare"
}

func (s *Solver) Present(ch *cmapi.ChallengeRequest) error {
	p, err := s.buildDNSProvider(ch)
	if err != nil {
		return err
	}

	err = p.Present(ch.Challenge.Spec.DNSName, ch.ResolvedFQDN, ch.Challenge.Spec.Key)
	if err != nil {
		return err
	}

	return nil
}

func (s *Solver) CleanUp(ch *cmapi.ChallengeRequest) error {
	p, err := s.buildDNSProvider(ch)
	if err != nil {
		return err
	}

	err = p.CleanUp(ch.Challenge.Spec.DNSName, ch.ResolvedFQDN, ch.Challenge.Spec.Key)
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

func (s *Solver) loadConfig(cfgJSON extapi.JSON) (config, error) {
	cfg := config{}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (s *Solver) loadAPIKey(ch *cmapi.ChallengeRequest, cfg config) (string, error) {
	secret, err := s.secretLister.Secrets(ch.ResourceNamespace).Get(cfg.APIKeySecretRef.Name)
	if err != nil {
		return "", err
	}
	apiKeyData, ok := secret.Data[cfg.APIKeySecretRef.Key]
	if !ok {
		return "", fmt.Errorf("no data for key %q found in secret '%s/%s'", cfg.APIKeySecretRef.Key, ch.ResourceNamespace, cfg.APIKeySecretRef.Name)
	}
	return string(apiKeyData), nil
}

func (s *Solver) buildDNSProvider(ch *cmapi.ChallengeRequest) (*DNSProvider, error) {
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

	// TODO: remove dns01Nameservers
	p, err := NewDNSProviderCredentials(cfg.Email, apiKey, []string{"1.1.1.1:53"})
	if err != nil {
		return nil, fmt.Errorf("error initializing DNS provider: %v", err)
	}

	return p, nil
}
