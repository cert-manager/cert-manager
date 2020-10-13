/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package client

import (
	"fmt"
	"time"

	vcert "github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	corelisters "k8s.io/client-go/listers/core/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/issuer/venafi/client/api"
)

const (
	tppUsernameKey    = "username"
	tppPasswordKey    = "password"
	tppAccessTokenKey = "access-token"

	defaultAPIKeyKey = "api-key"
)

type VenafiClientBuilder func(namespace string, secretsLister corelisters.SecretLister,
	issuer cmapi.GenericIssuer) (Interface, error)

// Interface implements a Venafi client
type Interface interface {
	RequestCertificate(csrPEM []byte, duration time.Duration, customFields []api.CustomField) (string, error)
	RetrieveCertificate(pickupID string, csrPEM []byte, duration time.Duration, customFields []api.CustomField) ([]byte, error)
	Ping() error
	ReadZoneConfiguration() (*endpoint.ZoneConfiguration, error)
	SetClient(endpoint.Connector)
}

// Venafi is a implementation of vcert library to manager certificates from TPP or Venafi Cloud
type Venafi struct {
	// Namespace in which to read resources related to this Issuer from.
	// For Issuers, this will be the namespace of the Issuer.
	// For ClusterIssuers, this will be the cluster resource namespace.
	namespace     string
	secretsLister corelisters.SecretLister

	vcertClient connector
}

// connector exposes a subset of the vcert Connector interface to make stubbing
// out its functionality during tests easier.
type connector interface {
	Ping() (err error)
	ReadZoneConfiguration() (config *endpoint.ZoneConfiguration, err error)
	RequestCertificate(req *certificate.Request) (requestID string, err error)
	RetrieveCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error)
	RenewCertificate(req *certificate.RenewalRequest) (requestID string, err error)
}

func New(namespace string, secretsLister corelisters.SecretLister, issuer cmapi.GenericIssuer) (Interface, error) {
	cfg, err := configForIssuer(issuer, secretsLister, namespace)
	if err != nil {
		return nil, err
	}

	vcertClient, err := vcert.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("error creating Venafi client: %s", err.Error())
	}

	return &Venafi{
		namespace:     namespace,
		secretsLister: secretsLister,
		vcertClient:   vcertClient,
	}, nil
}

// configForIssuer will convert a cert-manager Venafi issuer into a vcert.Config
// that can be used to instantiate an API client.
func configForIssuer(iss cmapi.GenericIssuer, secretsLister corelisters.SecretLister, namespace string) (*vcert.Config, error) {
	venCfg := iss.GetSpec().Venafi
	switch {
	case venCfg.TPP != nil:
		tpp := venCfg.TPP
		tppSecret, err := secretsLister.Secrets(namespace).Get(tpp.CredentialsRef.Name)
		if err != nil {
			return nil, err
		}

		username := string(tppSecret.Data[tppUsernameKey])
		password := string(tppSecret.Data[tppPasswordKey])
		accessToken := string(tppSecret.Data[tppAccessTokenKey])
		caBundle := string(tpp.CABundle)

		return &vcert.Config{
			ConnectorType: endpoint.ConnectorTypeTPP,
			BaseUrl:       tpp.URL,
			Zone:          venCfg.Zone,
			// always enable verbose logging for now
			LogVerbose:      true,
			ConnectionTrust: caBundle,
			Credentials: &endpoint.Authentication{
				User:        username,
				Password:    password,
				AccessToken: accessToken,
			},
		}, nil
	case venCfg.Cloud != nil:
		cloud := venCfg.Cloud
		cloudSecret, err := secretsLister.Secrets(namespace).Get(cloud.APITokenSecretRef.Name)
		if err != nil {
			return nil, err
		}

		k := defaultAPIKeyKey
		if cloud.APITokenSecretRef.Key != "" {
			k = cloud.APITokenSecretRef.Key
		}
		apiKey := string(cloudSecret.Data[k])

		return &vcert.Config{
			ConnectorType: endpoint.ConnectorTypeCloud,
			BaseUrl:       cloud.URL,
			Zone:          venCfg.Zone,
			// always enable verbose logging for now
			LogVerbose: true,
			Credentials: &endpoint.Authentication{
				APIKey: apiKey,
			},
		}, nil
	}

	return nil, fmt.Errorf("neither Venafi Cloud or TPP configuration found")
}

func (v *Venafi) Ping() error {
	return v.vcertClient.Ping()
}

func (v *Venafi) ReadZoneConfiguration() (*endpoint.ZoneConfiguration, error) {
	return v.vcertClient.ReadZoneConfiguration()
}

func (v *Venafi) SetClient(client endpoint.Connector) {
	v.vcertClient = client
}
