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

package acmedns

import (
	"encoding/json"
	"fmt"
	"time"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	restclient "k8s.io/client-go/rest"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

type Solver struct {
	secretLister corelisters.SecretLister
}

func (s *Solver) Name() string {
	return "acmedns"
}

func (s *Solver) Present(ch *cmapi.ChallengeRequest) error {
	p, err := s.buildDNSProvider(ch)
	if err != nil {
		return err
	}

	err = p.Present(ch.Challenge.Spec.DNSName, ch.Challenge.Spec.Key)
	if err != nil {
		return err
	}

	return nil
}

func (s *Solver) CleanUp(ch *cmapi.ChallengeRequest) error {
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

func (s *Solver) loadConfig(cfgJSON extapi.JSON) (*cmapi.ACMEIssuerDNS01ProviderAcmeDNS, error) {
	cfg := cmapi.ACMEIssuerDNS01ProviderAcmeDNS{}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return nil, fmt.Errorf("error decoding solver config: %v", err)
	}

	return &cfg, nil
}

func (s *Solver) loadAccountData(ch *cmapi.ChallengeRequest, cfg *cmapi.ACMEIssuerDNS01ProviderAcmeDNS) ([]byte, error) {
	secret, err := s.secretLister.Secrets(ch.ResourceNamespace).Get(cfg.AccountSecret.Name)
	if err != nil {
		return nil, err
	}
	accountData, ok := secret.Data[cfg.AccountSecret.Key]
	if !ok {
		return nil, fmt.Errorf("no data for key %q found in secret '%s/%s'", cfg.AccountSecret.Key, ch.ResourceNamespace, cfg.AccountSecret.Name)
	}
	return accountData, nil
}

func (s *Solver) buildDNSProvider(ch *cmapi.ChallengeRequest) (*DNSProvider, error) {
	if ch.Config == nil {
		return nil, fmt.Errorf("no challenge solver config provided")
	}

	cfg, err := s.loadConfig(*ch.Config)
	if err != nil {
		return nil, err
	}

	accountData, err := s.loadAccountData(ch, cfg)
	if err != nil {
		return nil, err
	}

	p, err := NewDNSProviderHostBytes(cfg.Host, accountData)
	if err != nil {
		return nil, fmt.Errorf("error initializing DNS provider: %v", err)
	}

	return p, nil
}
