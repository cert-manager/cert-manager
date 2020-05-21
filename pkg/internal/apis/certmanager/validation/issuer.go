/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package validation

import (
	"crypto/x509"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmacme "github.com/jetstack/cert-manager/pkg/internal/apis/acme"
	"github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
	"github.com/jetstack/cert-manager/pkg/internal/apis/certmanager/validation/util"
	cmmeta "github.com/jetstack/cert-manager/pkg/internal/apis/meta"
)

// Validation functions for cert-manager v1alpha2 Issuer types

func ValidateIssuer(obj runtime.Object) field.ErrorList {
	iss := obj.(*certmanager.Issuer)
	allErrs := ValidateIssuerSpec(&iss.Spec, field.NewPath("spec"))
	return allErrs
}

func ValidateIssuerSpec(iss *certmanager.IssuerSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	el = ValidateIssuerConfig(&iss.IssuerConfig, fldPath)
	return el
}

func ValidateIssuerConfig(iss *certmanager.IssuerConfig, fldPath *field.Path) field.ErrorList {
	numConfigs := 0
	el := field.ErrorList{}
	if iss.ACME != nil {
		numConfigs++
		el = append(el, ValidateACMEIssuerConfig(iss.ACME, fldPath.Child("acme"))...)
	}
	if iss.CA != nil {
		numConfigs++
		el = append(el, ValidateCAIssuerConfig(iss.CA, fldPath.Child("ca"))...)
	}
	if iss.SelfSigned != nil {
		numConfigs++
		el = append(el, ValidateSelfSignedIssuerConfig(iss.SelfSigned, fldPath.Child("selfSigned"))...)
	}
	if iss.Vault != nil {
		numConfigs++
		el = append(el, ValidateVaultIssuerConfig(iss.Vault, fldPath.Child("vault"))...)
	}
	if iss.Venafi != nil {
		numConfigs++
		el = append(el, ValidateVenafiIssuerConfig(iss.Venafi, fldPath.Child("venafi"))...)
	}

	if numConfigs == 0 {
		el = append(el, field.Required(fldPath, "at least one issuer must be configured"))
	} else if numConfigs > 1 {
		el = append(el, field.Forbidden(fldPath, "may not specify more than one issuer type"))
	}

	return el
}

func ValidateACMEIssuerConfig(iss *cmacme.ACMEIssuer, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if len(iss.PrivateKey.Name) == 0 {
		el = append(el, field.Required(fldPath.Child("privateKeySecretRef", "name"), "private key secret name is a required field"))
	}
	if len(iss.Server) == 0 {
		el = append(el, field.Required(fldPath.Child("server"), "acme server URL is a required field"))
	}

	if eab := iss.ExternalAccountBinding; eab != nil {
		eabFldPath := fldPath.Child("externalAccountBinding")
		if len(eab.KeyID) == 0 {
			el = append(el, field.Required(eabFldPath.Child("keyID"), "the keyID field is required when using externalAccountBinding"))
		}

		el = append(el, ValidateSecretKeySelector(&eab.Key, eabFldPath.Child("keySecretRef"))...)

		if len(eab.KeyAlgorithm) == 0 {
			el = append(el, field.Required(eabFldPath.Child("keyAlgorithm"), "the keyAlgorithm field is required when using externalAccountBinding"))
		}
	}

	for i, sol := range iss.Solvers {
		el = append(el, ValidateACMEIssuerChallengeSolverConfig(&sol, fldPath.Child("solvers").Index(i))...)
	}

	return el
}

func ValidateACMEIssuerChallengeSolverConfig(sol *cmacme.ACMEChallengeSolver, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	numProviders := 0
	if sol.HTTP01 != nil {
		numProviders++
		el = append(el, ValidateACMEIssuerChallengeSolverHTTP01Config(sol.HTTP01, fldPath.Child("http01"))...)
	}
	if sol.DNS01 != nil {
		numProviders++
		el = append(el, ValidateACMEChallengeSolverDNS01(sol.DNS01, fldPath.Child("dns01"))...)
	}
	if numProviders == 0 {
		el = append(el, field.Required(fldPath, "no solver type configured"))
	} else if numProviders > 1 {
		el = append(el, field.Forbidden(fldPath, "may not specify more than one solver type in a single solver"))
	}

	return el
}

func ValidateACMEIssuerChallengeSolverHTTP01Config(http01 *cmacme.ACMEChallengeSolverHTTP01, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	numDefined := 0
	if http01.Ingress != nil {
		numDefined++
		el = append(el, ValidateACMEIssuerChallengeSolverHTTP01IngressConfig(http01.Ingress, fldPath.Child("ingress"))...)
	}

	if numDefined == 0 {
		el = append(el, field.Required(fldPath, "no HTTP01 solver type configured"))
	}

	return el
}

func ValidateACMEIssuerChallengeSolverHTTP01IngressConfig(ingress *cmacme.ACMEChallengeSolverHTTP01Ingress, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	if ingress.Class != nil && len(ingress.Name) > 0 {
		el = append(el, field.Forbidden(fldPath, "only one of 'name' or 'class' should be specified"))
	}
	switch ingress.ServiceType {
	case "", corev1.ServiceTypeClusterIP, corev1.ServiceTypeNodePort:
	default:
		el = append(el, field.Invalid(fldPath.Child("serviceType"), ingress.ServiceType, `must be empty, "ClusterIP" or "NodePort"`))
	}

	return el
}

func ValidateCAIssuerConfig(iss *certmanager.CAIssuer, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if len(iss.SecretName) == 0 {
		el = append(el, field.Required(fldPath.Child("secretName"), ""))
	}
	return el
}

func ValidateSelfSignedIssuerConfig(iss *certmanager.SelfSignedIssuer, fldPath *field.Path) field.ErrorList {
	return nil
}

func ValidateVaultIssuerConfig(iss *certmanager.VaultIssuer, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if len(iss.Server) == 0 {
		el = append(el, field.Required(fldPath.Child("server"), ""))
	}
	if len(iss.Path) == 0 {
		el = append(el, field.Required(fldPath.Child("path"), ""))
	}

	// check if caBundle is valid
	certs := iss.CABundle
	if len(certs) > 0 {
		caCertPool := x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(certs)
		if !ok {
			el = append(el, field.Invalid(fldPath.Child("caBundle"), "", "Specified CA bundle is invalid"))
		}
	}

	return el
	// TODO: add validation for Vault authentication types
}

func ValidateVenafiIssuerConfig(iss *certmanager.VenafiIssuer, fldPath *field.Path) field.ErrorList {
	//TODO: make extended validation fro fake\tpp\cloud modes
	return nil
}

func ValidateACMEChallengeSolverDNS01(p *cmacme.ACMEChallengeSolverDNS01, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	numProviders := 0
	if p.Akamai != nil {
		numProviders++
		el = append(el, ValidateSecretKeySelector(&p.Akamai.AccessToken, fldPath.Child("akamai", "accessToken"))...)
		el = append(el, ValidateSecretKeySelector(&p.Akamai.ClientSecret, fldPath.Child("akamai", "clientSecret"))...)
		el = append(el, ValidateSecretKeySelector(&p.Akamai.ClientToken, fldPath.Child("akamai", "clientToken"))...)
		if len(p.Akamai.ServiceConsumerDomain) == 0 {
			el = append(el, field.Required(fldPath.Child("akamai", "serviceConsumerDomain"), ""))
		}
	}
	if p.AzureDNS != nil {
		numProviders++
		// if ClientID or ClientSecret or TenantID are defined then all of ClientID, ClientSecret and tenantID must be defined
		// We check things separately because
		if len(p.AzureDNS.ClientID) > 0 || len(p.AzureDNS.TenantID) > 0 || p.AzureDNS.ClientSecret != nil {
			if len(p.AzureDNS.ClientID) == 0 {
				el = append(el, field.Required(fldPath.Child("azuredns", "clientID"), ""))
			}
			if p.AzureDNS.ClientSecret == nil {
				el = append(el, field.Required(fldPath.Child("azuredns", "clientSecretSecretRef"), ""))
			} else {
				el = append(el, ValidateSecretKeySelector(p.AzureDNS.ClientSecret, fldPath.Child("azuredns", "clientSecretSecretRef"))...)
			}
			if len(p.AzureDNS.TenantID) == 0 {
				el = append(el, field.Required(fldPath.Child("azuredns", "tenantID"), ""))
			}
		}
		// SubscriptionID must always be defined
		if len(p.AzureDNS.SubscriptionID) == 0 {
			el = append(el, field.Required(fldPath.Child("azuredns", "subscriptionID"), ""))
		}
		// ResourceGroupName must always be defined
		if len(p.AzureDNS.ResourceGroupName) == 0 {
			el = append(el, field.Required(fldPath.Child("azuredns", "resourceGroupName"), ""))
		}
		switch p.AzureDNS.Environment {
		case "", cmacme.AzurePublicCloud, cmacme.AzureChinaCloud, cmacme.AzureGermanCloud, cmacme.AzureUSGovernmentCloud:
		default:
			el = append(el, field.Invalid(fldPath.Child("azuredns", "environment"), p.AzureDNS.Environment,
				fmt.Sprintf("must be either empty or one of %s, %s, %s or %s", cmacme.AzurePublicCloud, cmacme.AzureChinaCloud, cmacme.AzureGermanCloud, cmacme.AzureUSGovernmentCloud)))
		}

	}
	if p.CloudDNS != nil {
		numProviders++
		// if service account is not nil we validate the entire secret key
		// selector
		if p.CloudDNS.ServiceAccount != nil {
			el = append(el, ValidateSecretKeySelector(p.CloudDNS.ServiceAccount, fldPath.Child("clouddns", "serviceAccountSecretRef"))...)
		}
		if len(p.CloudDNS.Project) == 0 {
			el = append(el, field.Required(fldPath.Child("clouddns", "project"), ""))
		}
	}
	if p.Cloudflare != nil {
		numProviders++
		if p.Cloudflare.APIKey != nil {
			el = append(el, ValidateSecretKeySelector(p.Cloudflare.APIKey, fldPath.Child("cloudflare", "apiKeySecretRef"))...)
		}
		if p.Cloudflare.APIToken != nil {
			el = append(el, ValidateSecretKeySelector(p.Cloudflare.APIToken, fldPath.Child("cloudflare", "apiTokenSecretRef"))...)
		}
		if p.Cloudflare.APIKey != nil && p.Cloudflare.APIToken != nil {
			el = append(el, field.Forbidden(fldPath.Child("cloudflare"), "apiKeySecretRef and apiTokenSecretRef cannot both be specified"))
		}
		if p.Cloudflare.APIKey == nil && p.Cloudflare.APIToken == nil {
			el = append(el, field.Required(fldPath.Child("cloudflare"), "apiKeySecretRef or apiTokenSecretRef is required"))
		}
		if len(p.Cloudflare.Email) == 0 {
			el = append(el, field.Required(fldPath.Child("cloudflare", "email"), ""))
		}
	}
	if p.Route53 != nil {
		numProviders++
		// region is the only required field for route53 as ambient credentials can be used instead
		if len(p.Route53.Region) == 0 {
			el = append(el, field.Required(fldPath.Child("route53", "region"), ""))
		}
	}
	if p.AcmeDNS != nil {
		numProviders++
		el = append(el, ValidateSecretKeySelector(&p.AcmeDNS.AccountSecret, fldPath.Child("acmedns", "accountSecretRef"))...)
		if len(p.AcmeDNS.Host) == 0 {
			el = append(el, field.Required(fldPath.Child("acmedns", "host"), ""))
		}
	}

	if p.DigitalOcean != nil {
		numProviders++
		el = append(el, ValidateSecretKeySelector(&p.DigitalOcean.Token, fldPath.Child("digitalocean", "tokenSecretRef"))...)
	}
	if p.RFC2136 != nil {
		numProviders++
		// Nameserver is the only required field for RFC2136
		if len(p.RFC2136.Nameserver) == 0 {
			el = append(el, field.Required(fldPath.Child("rfc2136", "nameserver"), ""))
		} else {
			if _, err := util.ValidNameserver(p.RFC2136.Nameserver); err != nil {
				el = append(el, field.Invalid(fldPath.Child("rfc2136", "nameserver"), p.RFC2136.Nameserver, "nameserver must be set in the form host:port where host is an IPv4 address, an enclosed IPv6 address or a hostname and port is an optional port number."))
			}
		}

		if len(p.RFC2136.TSIGKeyName) > 0 {
			el = append(el, ValidateSecretKeySelector(&p.RFC2136.TSIGSecret, fldPath.Child("rfc2136", "tsigSecretSecretRef"))...)
		}

		if len(ValidateSecretKeySelector(&p.RFC2136.TSIGSecret, fldPath.Child("rfc2136", "tsigSecretSecretRef"))) == 0 {
			if len(p.RFC2136.TSIGKeyName) <= 0 {
				el = append(el, field.Required(fldPath.Child("rfc2136", "tsigKeyName"), ""))
			}
		}
	}
	if p.Webhook != nil {
		numProviders++
		if len(p.Webhook.SolverName) == 0 {
			el = append(el, field.Required(fldPath.Child("webhook", "solverName"), "solver name must be specified"))
		}
	}
	if numProviders == 0 {
		el = append(el, field.Required(fldPath, "no DNS01 provider configured"))
	} else if numProviders > 1 {
		el = append(el, field.Forbidden(fldPath, "may not specify more than one provider type"))
	}

	return el
}

func ValidateSecretKeySelector(sks *cmmeta.SecretKeySelector, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if sks.Name == "" {
		el = append(el, field.Required(fldPath.Child("name"), "secret name is required"))
	}
	if sks.Key == "" {
		el = append(el, field.Required(fldPath.Child("key"), "secret key is required"))
	}
	return el
}
