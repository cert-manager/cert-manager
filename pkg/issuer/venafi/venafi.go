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

package venafi

import (
	"fmt"

	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	corev1 "k8s.io/api/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

const (
	tppUsernameKey = "username"
	tppPasswordKey = "password"

	defaultAPIKeyKey = "api-key"
)

// Venafi is a implementation of govcert library to manager certificates from TPP or Venafi Cloud
type Venafi struct {
	issuer cmapi.GenericIssuer
	*controller.Context

	// Namespace in which to read resources related to this Issuer from.
	// For Issuers, this will be the namespace of the Issuer.
	// For ClusterIssuers, this will be the cluster resource namespace.
	resourceNamespace string
	secretsLister     corelisters.SecretLister

	client connector
}

// connector exposes a subset of the vcert Connector interface to make stubbing
// out its functionality during tests easier.
type connector interface {
	Ping() (err error)
	ReadZoneConfiguration(zone string) (config *endpoint.ZoneConfiguration, err error)
	RequestCertificate(req *certificate.Request, zone string) (requestID string, err error)
	RetrieveCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error)
	RenewCertificate(req *certificate.RenewalRequest) (requestID string, err error)
}

func NewVenafi(ctx *controller.Context, issuer cmapi.GenericIssuer) (issuer.Interface, error) {
	secretsLister := ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister()
	resourceNamespace := ctx.IssuerOptions.ResourceNamespace(issuer)

	cfg, err := configForIssuer(issuer, secretsLister, resourceNamespace)
	if err != nil {
		ctx.Recorder.Eventf(issuer, corev1.EventTypeWarning, "FailedInit", "Failed to initialise issuer: %v", err)
		return nil, err
	}

	client, err := vcert.NewClient(cfg)
	if err != nil {
		ctx.Recorder.Eventf(issuer, corev1.EventTypeWarning, "FailedInit", "Failed to create Venafi client: %v", err)
		return nil, fmt.Errorf("error creating Venafi client: %s", err.Error())
	}

	return &Venafi{
		issuer:            issuer,
		Context:           ctx,
		resourceNamespace: resourceNamespace,
		secretsLister:     secretsLister,
		client:            client,
	}, nil
}

// configForIssuer will convert a cert-manager Venafi issuer into a vcert.Config
// that can be used to instantiate an API client.
func configForIssuer(iss cmapi.GenericIssuer, secretsLister corelisters.SecretLister, resourceNamespace string) (*vcert.Config, error) {
	venCfg := iss.GetSpec().Venafi
	switch {
	case venCfg.TPP != nil:
		tpp := venCfg.TPP
		tppSecret, err := secretsLister.Secrets(resourceNamespace).Get(tpp.CredentialsRef.Name)
		if err != nil {
			return nil, fmt.Errorf("error loading TPP credentials: %v", err)
		}

		username := tppSecret.Data[tppUsernameKey]
		password := tppSecret.Data[tppPasswordKey]

		caBundle := ""
		if len(tpp.CABundle) > 0 {
			caBundle = string(tpp.CABundle)
		}

		return &vcert.Config{
			ConnectorType: endpoint.ConnectorTypeTPP,
			BaseUrl:       tpp.URL,
			Zone:          venCfg.Zone,
			// always enable verbose logging for now
			LogVerbose:      true,
			ConnectionTrust: caBundle,
			Credentials: &endpoint.Authentication{
				User:     string(username),
				Password: string(password),
			},
		}, nil

	case venCfg.Cloud != nil:
		cloud := venCfg.Cloud
		cloudSecret, err := secretsLister.Secrets(resourceNamespace).Get(cloud.APITokenSecretRef.Name)
		if err != nil {
			return nil, fmt.Errorf("error loading TPP credentials: %v", err)
		}

		k := defaultAPIKeyKey
		if cloud.APITokenSecretRef.Key != "" {
			k = cloud.APITokenSecretRef.Key
		}
		apiKey := cloudSecret.Data[k]

		return &vcert.Config{
			ConnectorType: endpoint.ConnectorTypeCloud,
			BaseUrl:       cloud.URL,
			Zone:          venCfg.Zone,
			// always enable verbose logging for now
			LogVerbose: true,
			Credentials: &endpoint.Authentication{
				APIKey: string(apiKey),
			},
		}, nil

	default:
		return nil, fmt.Errorf("neither Venafi Cloud or TPP configuration found")
	}
}

func init() {
	issuer.RegisterIssuer(apiutil.IssuerVenafi, NewVenafi)
}
