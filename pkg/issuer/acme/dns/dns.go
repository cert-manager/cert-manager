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

package dns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/pkg/errors"
	corev1listers "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/acmedns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/akamai"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/azuredns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/clouddns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/cloudflare"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/rfc2136"
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
	cloudDNS   func(project string, serviceAccount []byte, dns01Nameservers []string, ambient bool) (*clouddns.DNSProvider, error)
	cloudFlare func(email, apikey string, dns01Nameservers []string) (*cloudflare.DNSProvider, error)
	route53    func(accessKey, secretKey, hostedZoneID, region string, ambient bool, dns01Nameservers []string) (*route53.DNSProvider, error)
	azureDNS   func(clientID, clientSecret, subscriptionID, tenentID, resourceGroupName, hostedZoneName string, dns01Nameservers []string) (*azuredns.DNSProvider, error)
	acmeDNS    func(host string, accountJson []byte, dns01Nameservers []string) (*acmedns.DNSProvider, error)
	rfc2136    func(nameserver, tsigAlgorithm, tsigKeyName, tsigSecret string, dns01Nameservers []string) (*rfc2136.DNSProvider, error)
}

// Solver is a solver for the acme dns01 challenge.
// Given a Certificate object, it determines the correct DNS provider based on
// the certificate, and configures it based on the referenced issuer.
type Solver struct {
	*controller.Context
	secretLister            corev1listers.SecretLister
	dnsProviderConstructors dnsProviderConstructors
}

// Present performs the work to configure DNS to resolve a DNS01 challenge.
func (s *Solver) Present(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	if ch.Spec.Config.DNS01 == nil {
		return fmt.Errorf("challenge dns config must be specified")
	}

	slv, err := s.solverForChallenge(issuer, ch)
	if err != nil {
		return err
	}

	glog.Infof("Presenting DNS01 challenge for domain %q", ch.Spec.DNSName)
	return slv.Present(ch.Spec.DNSName, ch.Spec.Token, ch.Spec.Key)
}

// Check verifies that the DNS records for the ACME challenge have propagated.
func (s *Solver) Check(ch *v1alpha1.Challenge) (bool, error) {
	fqdn, value, ttl, err := util.DNS01Record(ch.Spec.DNSName, ch.Spec.Key, s.DNS01Nameservers)
	if err != nil {
		return false, err
	}

	glog.Infof("Checking DNS propagation for %q using name servers: %v", ch.Spec.DNSName, s.Context.DNS01Nameservers)

	ok, err := util.PreCheckDNS(fqdn, value, s.Context.DNS01Nameservers)
	if err != nil {
		return false, err
	}
	if !ok {
		glog.Infof("DNS record for %q not yet propagated", ch.Spec.DNSName)
		return false, nil
	}

	glog.Infof("Waiting DNS record TTL (%ds) to allow propagation of DNS record for domain %q", ttl, fqdn)
	time.Sleep(time.Second * time.Duration(ttl))
	glog.Infof("ACME DNS01 validation record propagated for %q", fqdn)

	return true, nil
}

// CleanUp removes DNS records which are no longer needed after
// certificate issuance.
func (s *Solver) CleanUp(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	if ch.Spec.Config.DNS01 == nil {
		return fmt.Errorf("challenge dns config must be specified")
	}

	slv, err := s.solverForChallenge(issuer, ch)
	if err != nil {
		return err
	}

	return slv.CleanUp(ch.Spec.DNSName, ch.Spec.Token, ch.Spec.Key)
}

// solverForChallenge returns a Solver for the given providerName.
// The providerName is the name of an ACME DNS-01 challenge provider as
// specified on the Issuer resource for the Solver.
func (s *Solver) solverForChallenge(issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) (solver, error) {
	resourceNamespace := s.ResourceNamespace(issuer)
	canUseAmbientCredentials := s.CanUseAmbientCredentials(issuer)

	providerName := ch.Spec.Config.DNS01.Provider
	if providerName == "" {
		return nil, fmt.Errorf("dns01 challenge provider name must be set")
	}

	providerConfig, err := issuer.GetSpec().ACME.DNS01.Provider(providerName)
	if err != nil {
		return nil, err
	}

	var impl solver
	switch {
	case providerConfig.Akamai != nil:
		clientToken, err := s.loadSecretData(&providerConfig.Akamai.ClientToken, resourceNamespace)
		if err != nil {
			return nil, errors.Wrap(err, "error getting akamai client token")
		}

		clientSecret, err := s.loadSecretData(&providerConfig.Akamai.ClientSecret, resourceNamespace)
		if err != nil {
			return nil, errors.Wrap(err, "error getting akamai client secret")
		}

		accessToken, err := s.loadSecretData(&providerConfig.Akamai.AccessToken, resourceNamespace)
		if err != nil {
			return nil, errors.Wrap(err, "error getting akamai access token")
		}

		impl, err = akamai.NewDNSProvider(
			providerConfig.Akamai.ServiceConsumerDomain,
			string(clientToken),
			string(clientSecret),
			string(accessToken),
			s.DNS01Nameservers)
		if err != nil {
			return nil, errors.Wrap(err, "error instantiating akamai challenge solver")
		}
	case providerConfig.CloudDNS != nil:
		var keyData []byte

		// if the serviceAccount.name field is set, we will load credentials from
		// that secret.
		// If it is not set, we will attempt to instantiate the provider using
		// ambient credentials (if enabled).
		if providerConfig.CloudDNS.ServiceAccount.Name != "" {
			saSecret, err := s.secretLister.Secrets(resourceNamespace).Get(providerConfig.CloudDNS.ServiceAccount.Name)
			if err != nil {
				return nil, fmt.Errorf("error getting clouddns service account: %s", err)
			}

			saKey := providerConfig.CloudDNS.ServiceAccount.Key
			keyData = saSecret.Data[saKey]
			if len(keyData) == 0 {
				return nil, fmt.Errorf("specfied key %q not found in secret %s/%s", saKey, saSecret.Namespace, saSecret.Name)
			}
		}

		// attempt to construct the cloud dns provider
		impl, err = s.dnsProviderConstructors.cloudDNS(providerConfig.CloudDNS.Project, keyData, s.DNS01Nameservers, s.CanUseAmbientCredentials(issuer))
		if err != nil {
			return nil, fmt.Errorf("error instantiating google clouddns challenge solver: %s", err)
		}
	case providerConfig.Cloudflare != nil:
		apiKeySecret, err := s.secretLister.Secrets(resourceNamespace).Get(providerConfig.Cloudflare.APIKey.Name)
		if err != nil {
			return nil, fmt.Errorf("error getting cloudflare service account: %s", err)
		}

		email := providerConfig.Cloudflare.Email
		apiKey := string(apiKeySecret.Data[providerConfig.Cloudflare.APIKey.Key])

		impl, err = s.dnsProviderConstructors.cloudFlare(email, apiKey, s.DNS01Nameservers)
		if err != nil {
			return nil, fmt.Errorf("error instantiating cloudflare challenge solver: %s", err)
		}
	case providerConfig.Route53 != nil:
		secretAccessKey := ""
		if providerConfig.Route53.SecretAccessKey.Name != "" {
			secretAccessKeySecret, err := s.secretLister.Secrets(resourceNamespace).Get(providerConfig.Route53.SecretAccessKey.Name)
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
			canUseAmbientCredentials,
			s.DNS01Nameservers,
		)
		if err != nil {
			return nil, fmt.Errorf("error instantiating route53 challenge solver: %s", err)
		}
	case providerConfig.AzureDNS != nil:
		clientSecret, err := s.secretLister.Secrets(resourceNamespace).Get(providerConfig.AzureDNS.ClientSecret.Name)
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
			s.DNS01Nameservers,
		)
		if err != nil {
			return nil, fmt.Errorf("error instantiating azuredns challenge solver: %s", err)
		}
	case providerConfig.AcmeDNS != nil:
		accountSecret, err := s.secretLister.Secrets(resourceNamespace).Get(providerConfig.AcmeDNS.AccountSecret.Name)
		if err != nil {
			return nil, fmt.Errorf("error getting acmedns accounts secret: %s", err)
		}

		accountSecretBytes, ok := accountSecret.Data[providerConfig.AcmeDNS.AccountSecret.Key]
		if !ok {
			return nil, fmt.Errorf("error getting acmedns accounts secret: key '%s' not found in secret", providerConfig.AcmeDNS.AccountSecret.Key)
		}

		impl, err = s.dnsProviderConstructors.acmeDNS(
			providerConfig.AcmeDNS.Host,
			accountSecretBytes,
			s.DNS01Nameservers,
		)
		if err != nil {
			return nil, fmt.Errorf("error instantiating acmedns challenge solver: %s", err)
		}
	case providerConfig.RFC2136 != nil:
		var secret string
		if len(providerConfig.RFC2136.TSIGSecret.Name) > 0 {
			tsigSecret, err := s.secretLister.Secrets(resourceNamespace).Get(providerConfig.RFC2136.TSIGSecret.Name)
			if err != nil {
				return nil, fmt.Errorf("error getting rfc2136 service account: %s", err.Error())
			}
			secretBytes, ok := tsigSecret.Data[providerConfig.RFC2136.TSIGSecret.Key]
			if !ok {
				return nil, fmt.Errorf("error getting rfc2136 secret key: key '%s' not found in secret", providerConfig.RFC2136.TSIGSecret.Key)
			}
			secret = string(secretBytes)
		}

		impl, err = s.dnsProviderConstructors.rfc2136(
			providerConfig.RFC2136.Nameserver,
			string(providerConfig.RFC2136.TSIGAlgorithm),
			providerConfig.RFC2136.TSIGKeyName,
			secret,
			s.DNS01Nameservers,
		)
		if err != nil {
			return nil, fmt.Errorf("error instantiating rfc2136 challenge solver: %s", err.Error())
		}
	default:
		return nil, fmt.Errorf("no dns provider config specified for provider %q", providerName)
	}

	return impl, nil
}

// NewSolver creates a Solver which can instantiate the appropriate DNS
// provider.
func NewSolver(ctx *controller.Context) *Solver {
	return &Solver{
		ctx,
		ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		dnsProviderConstructors{
			clouddns.NewDNSProvider,
			cloudflare.NewDNSProviderCredentials,
			route53.NewDNSProvider,
			azuredns.NewDNSProviderCredentials,
			acmedns.NewDNSProviderHostBytes,
			rfc2136.NewDNSProviderCredentials,
		},
	}
}

func (s *Solver) loadSecretData(selector *v1alpha1.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := s.secretLister.Secrets(ns).Get(selector.Name)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load secret %q", ns+"/"+selector.Name)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}

	return nil, errors.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}
