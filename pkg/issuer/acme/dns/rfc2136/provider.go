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

package rfc2136

import (
	"encoding/json"
	"fmt"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	restclient "k8s.io/client-go/rest"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

const SolverName = "rfc2136"

type Solver struct {
	secretLister internalinformers.SecretLister
	// options to apply when the lister gets initialized
	initOpts []Option

	// If specified, namespace will cause the rfc2136 provider to limit the
	// scope of the lister/watcher to a single namespace, to allow for
	// namespace restricted instances of cert-manager.
	namespace string
}

type Option func(*Solver)

func WithNamespace(ns string) Option {
	return func(s *Solver) {
		s.namespace = ns
	}
}

func WithSecretsLister(secretLister internalinformers.SecretLister) Option {
	return func(s *Solver) {
		s.secretLister = secretLister
	}
}

// InitializeResetLister is a hack to make RFC2136 solver fit the Solver
// interface. Unlike external solvers that are run as apiserver implementations,
// this solver is created as part of challenge controller initialization. That
// makes its Initialize method not fit the Solver interface very well as we want
// a way to initialize the solver with the existing Secrets lister rather than a
// new kube apiserver client. InitializeResetLister allows to reset secrets
// lister when Initialize function is called so that a new lister can be
// created. This is useful in tests where a kube clientset can get recreated for
// an existing solver (which would not happen when this solver runs normally).
func InitializeResetLister() Option {
	return func(s *Solver) {
		s.initOpts = []Option{func(s *Solver) { s.secretLister = nil }}
	}
}

func New(opts ...Option) *Solver {
	s := &Solver{}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Solver) Name() string {
	return SolverName
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
	for _, opt := range s.initOpts {
		opt(s)
	}
	// Only start a secrets informerfactory if it is needed (if the solver
	// is not already initialized with a secrets lister) This is legacy
	// functionality and is currently only used in integration tests.
	if s.secretLister == nil {
		cl, err := kubernetes.NewForConfig(kubeClientConfig)
		if err != nil {
			return err
		}

		// obtain a secret lister and start the informer factory to populate the
		// secret cache
		factory := informers.NewSharedInformerFactoryWithOptions(cl, time.Minute*5, informers.WithNamespace(s.namespace))
		s.secretLister = factory.Core().V1().Secrets().Lister()
		factory.Start(stopCh)
		factory.WaitForCacheSync(stopCh)
	}
	return nil
}

func (s *Solver) loadConfig(cfgJSON apiextensionsv1.JSON) (*cmacme.ACMEIssuerDNS01ProviderRFC2136, error) {
	cfg := cmacme.ACMEIssuerDNS01ProviderRFC2136{}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return nil, fmt.Errorf("error decoding solver config: %v", err)
	}

	return &cfg, nil
}

func loadSecretKeySelector(l corelisters.SecretNamespaceLister, sks cmmeta.SecretKeySelector, defaultKey string) ([]byte, error) {
	if sks.Name == "" {
		logf.Log.V(logf.WarnLevel).Info("rfc2136: secret name not specified")
		return nil, nil
	}
	key := defaultKey
	if sks.Key != "" {
		key = sks.Key
	}
	if key == "" {
		return nil, fmt.Errorf("key of data in Secret resource must be specified")
	}
	secret, err := l.Get(sks.Name)
	if err != nil {
		return nil, err
	}
	if d, ok := secret.Data[key]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("data entry with key %q not found in secret", key)
}

func (s *Solver) buildDNSProvider(ch *whapi.ChallengeRequest) (*DNSProvider, error) {
	if ch.Config == nil {
		return nil, fmt.Errorf("no challenge solver config provided")
	}

	cfg, err := s.loadConfig(*ch.Config)
	if err != nil {
		return nil, err
	}

	l := s.secretLister.Secrets(ch.ResourceNamespace)
	secret, err := loadSecretKeySelector(l, cfg.TSIGSecret, "")
	if err != nil {
		return nil, err
	}
	key := ""
	if len(secret) > 0 {
		key = string(secret)
	}

	return NewDNSProviderCredentials(cfg.Nameserver, cfg.TSIGAlgorithm, cfg.TSIGKeyName, key)
}
