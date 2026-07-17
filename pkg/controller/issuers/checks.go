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

package issuers

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func (c *controller) issuersForSecret(secret *corev1.Secret) ([]*v1.Issuer, error) {
	issuers, err := c.issuerLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing issuers: %s", err.Error())
	}

	var affected []*v1.Issuer
	for _, iss := range issuers {
		// only applicable for Issuer resources
		if iss.Namespace != secret.Namespace {
			continue
		}

		switch {
		case iss.Spec.ACME != nil:
			// Match account key, EAB key, and DNS-01 solver secrets so creating
			// a missing solver Secret re-queues the Issuer (see #9036).
			if acmeIssuerReferencesSecret(iss.Spec.ACME, secret.Name) {
				affected = append(affected, iss)
				continue
			}
		case iss.Spec.CA != nil:
			if iss.Spec.CA.SecretName == secret.Name {
				affected = append(affected, iss)
				continue
			}
		case iss.Spec.Venafi != nil:
			if iss.Spec.Venafi.TPP != nil {
				if iss.Spec.Venafi.TPP.CredentialsRef.Name == secret.Name {
					affected = append(affected, iss)
					continue
				}
				if iss.Spec.Venafi.TPP.CABundleSecretRef != nil {
					if iss.Spec.Venafi.TPP.CABundleSecretRef.Name == secret.Name {
						affected = append(affected, iss)
						continue
					}
				}
			}
			if iss.Spec.Venafi.Cloud != nil {
				if iss.Spec.Venafi.Cloud.APITokenSecretRef.Name == secret.Name {
					affected = append(affected, iss)
					continue
				}
			}
			if iss.Spec.Venafi.NGTS != nil {
				if iss.Spec.Venafi.NGTS.CredentialsRef.Name == secret.Name {
					affected = append(affected, iss)
					continue
				}
			}
		case iss.Spec.Vault != nil:
			if iss.Spec.Vault.Auth.TokenSecretRef != nil {
				if iss.Spec.Vault.Auth.TokenSecretRef.Name == secret.Name {
					affected = append(affected, iss)
					continue
				}
			}
			if iss.Spec.Vault.Auth.AppRole != nil {
				if iss.Spec.Vault.Auth.AppRole.SecretRef.Name == secret.Name {
					affected = append(affected, iss)
					continue
				}
			}
			if iss.Spec.Vault.Auth.Kubernetes != nil {
				if iss.Spec.Vault.Auth.Kubernetes.SecretRef.Name == secret.Name {
					affected = append(affected, iss)
					continue
				}
			}
			if iss.Spec.Vault.CABundleSecretRef != nil {
				if iss.Spec.Vault.CABundleSecretRef.Name == secret.Name {
					affected = append(affected, iss)
					continue
				}
			}
		}
	}

	return affected, nil
}

// acmeIssuerReferencesSecret reports whether the ACME issuer config references
// the given Secret name via the account private key, EAB key, or any DNS-01
// solver provider secret.
func acmeIssuerReferencesSecret(acme *cmacme.ACMEIssuer, secretName string) bool {
	if acme.PrivateKey.Name == secretName {
		return true
	}
	if acme.ExternalAccountBinding != nil && acme.ExternalAccountBinding.Key.Name == secretName {
		return true
	}
	for i := range acme.Solvers {
		if dns01SolverReferencesSecret(acme.Solvers[i].DNS01, secretName) {
			return true
		}
	}
	return false
}

// dns01SolverReferencesSecret matches the secret names collected by
// validation.ValidateACMEChallengeSolverDNS01 so creating or updating a solver
// Secret re-queues the Issuer that depends on it (see #9036).
func dns01SolverReferencesSecret(dns *cmacme.ACMEChallengeSolverDNS01, secretName string) bool {
	if dns == nil {
		return false
	}
	if dns.Akamai != nil {
		if dns.Akamai.AccessToken.Name == secretName ||
			dns.Akamai.ClientSecret.Name == secretName ||
			dns.Akamai.ClientToken.Name == secretName {
			return true
		}
	}
	if dns.AzureDNS != nil && dns.AzureDNS.ClientSecret != nil && dns.AzureDNS.ClientSecret.Name == secretName {
		return true
	}
	if dns.CloudDNS != nil && dns.CloudDNS.ServiceAccount != nil && dns.CloudDNS.ServiceAccount.Name == secretName {
		return true
	}
	if dns.Cloudflare != nil {
		if dns.Cloudflare.APIKey != nil && dns.Cloudflare.APIKey.Name == secretName {
			return true
		}
		if dns.Cloudflare.APIToken != nil && dns.Cloudflare.APIToken.Name == secretName {
			return true
		}
	}
	if dns.Route53 != nil {
		if dns.Route53.SecretAccessKey.Name == secretName {
			return true
		}
		if dns.Route53.SecretAccessKeyID != nil && dns.Route53.SecretAccessKeyID.Name == secretName {
			return true
		}
	}
	if dns.AcmeDNS != nil && dns.AcmeDNS.AccountSecret.Name == secretName {
		return true
	}
	if dns.DigitalOcean != nil && dns.DigitalOcean.Token.Name == secretName {
		return true
	}
	if dns.RFC2136 != nil && dns.RFC2136.TSIGSecret.Name == secretName {
		return true
	}
	return false
}
