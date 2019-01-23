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

package validation

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/rfc2136"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// Validation functions for cert-manager v1alpha1 Issuer types

func ValidateIssuer(iss *v1alpha1.Issuer) field.ErrorList {
	allErrs := ValidateIssuerSpec(&iss.Spec, field.NewPath("spec"))
	return allErrs
}

func ValidateIssuerSpec(iss *v1alpha1.IssuerSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	el = ValidateIssuerConfig(&iss.IssuerConfig, fldPath)
	return el
}

func ValidateIssuerConfig(iss *v1alpha1.IssuerConfig, fldPath *field.Path) field.ErrorList {
	numConfigs := 0
	el := field.ErrorList{}
	if iss.ACME != nil {
		if numConfigs > 0 {
			el = append(el, field.Forbidden(fldPath.Child("acme"), "may not specify more than one issuer type"))
		} else {
			numConfigs++
			el = append(el, ValidateACMEIssuerConfig(iss.ACME, fldPath.Child("acme"))...)
		}
	}
	if iss.CA != nil {
		if numConfigs > 0 {
			el = append(el, field.Forbidden(fldPath.Child("ca"), "may not specify more than one issuer type"))
		} else {
			numConfigs++
			el = append(el, ValidateCAIssuerConfig(iss.CA, fldPath.Child("ca"))...)
		}
	}
	if iss.SelfSigned != nil {
		if numConfigs > 0 {
			el = append(el, field.Forbidden(fldPath.Child("selfSigned"), "may not specify more than one issuer type"))
		} else {
			numConfigs++
			el = append(el, ValidateSelfSignedIssuerConfig(iss.SelfSigned, fldPath.Child("selfSigned"))...)
		}
	}
	if iss.Vault != nil {
		if numConfigs > 0 {
			el = append(el, field.Forbidden(fldPath.Child("vault"), "may not specify more than one issuer type"))
		} else {
			numConfigs++
			el = append(el, ValidateVaultIssuerConfig(iss.Vault, fldPath.Child("vault"))...)
		}
	}
	if iss.Venafi != nil {
		if numConfigs > 0 {
			el = append(el, field.Forbidden(fldPath.Child("venafi"), "may not specify more than one issuer type"))
		} else {
			numConfigs++
			el = append(el, ValidateVenafiIssuerConfig(iss.Venafi, fldPath.Child("venafi"))...)
		}
	}
	if numConfigs == 0 {
		el = append(el, field.Required(fldPath, "at least one issuer must be configured"))
	}

	return el
}

func ValidateACMEIssuerConfig(iss *v1alpha1.ACMEIssuer, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if len(iss.Email) == 0 {
		el = append(el, field.Required(fldPath.Child("email"), "email address is a required field"))
	}
	if len(iss.PrivateKey.Name) == 0 {
		el = append(el, field.Required(fldPath.Child("privateKeySecretRef", "name"), "private key secret name is a required field"))
	}
	if len(iss.Server) == 0 {
		el = append(el, field.Required(fldPath.Child("server"), "acme server URL is a required field"))
	}
	if iss.HTTP01 != nil {
		el = append(el, ValidateACMEIssuerHTTP01Config(iss.HTTP01, fldPath.Child("http01"))...)
	}
	if iss.DNS01 != nil {
		el = append(el, ValidateACMEIssuerDNS01Config(iss.DNS01, fldPath.Child("dns01"))...)
	}
	return el
}

func ValidateCAIssuerConfig(iss *v1alpha1.CAIssuer, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if len(iss.SecretName) == 0 {
		el = append(el, field.Required(fldPath.Child("secretName"), ""))
	}
	return el
}

func ValidateSelfSignedIssuerConfig(iss *v1alpha1.SelfSignedIssuer, fldPath *field.Path) field.ErrorList {
	return nil
}

func ValidateVaultIssuerConfig(iss *v1alpha1.VaultIssuer, fldPath *field.Path) field.ErrorList {
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

func ValidateVenafiIssuerConfig(iss *v1alpha1.VenafiIssuer, fldPath *field.Path) field.ErrorList {
	//TODO: make extended validation fro fake\tpp\cloud modes
	return nil
}

func ValidateACMEIssuerHTTP01Config(iss *v1alpha1.ACMEIssuerHTTP01Config, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	if len(iss.ServiceType) > 0 {
		validTypes := []corev1.ServiceType{
			corev1.ServiceTypeClusterIP,
			corev1.ServiceTypeNodePort,
		}
		validType := false
		for _, validTypeName := range validTypes {
			if iss.ServiceType == validTypeName {
				validType = true
				break
			}
		}
		if !validType {
			el = append(el, field.Invalid(fldPath.Child("serviceType"), iss.ServiceType, fmt.Sprintf("optional field serviceType must be one of %q", validTypes)))
		}
	}

	return el
}

func ValidateACMEIssuerDNS01Config(iss *v1alpha1.ACMEIssuerDNS01Config, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	providersFldPath := fldPath.Child("providers")
	for i, p := range iss.Providers {
		fldPath := providersFldPath.Index(i)
		if len(p.Name) == 0 {
			el = append(el, field.Required(fldPath.Child("name"), "name must be specified"))
		}
		// allow empty values for now, until we have a MutatingWebhook to apply
		// default values to fields.
		if len(p.CNAMEStrategy) > 0 {
			switch p.CNAMEStrategy {
			case v1alpha1.NoneStrategy:
			case v1alpha1.FollowStrategy:
			default:
				el = append(el, field.Invalid(fldPath.Child("cnameStrategy"), p.CNAMEStrategy, fmt.Sprintf("must be one of %q or %q", v1alpha1.NoneStrategy, v1alpha1.FollowStrategy)))
			}
		}
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
			if numProviders > 0 {
				el = append(el, field.Forbidden(fldPath.Child("azuredns"), "may not specify more than one provider type"))
			} else {
				numProviders++
				el = append(el, ValidateSecretKeySelector(&p.AzureDNS.ClientSecret, fldPath.Child("azuredns", "clientSecretSecretRef"))...)
				if len(p.AzureDNS.ClientID) == 0 {
					el = append(el, field.Required(fldPath.Child("azuredns", "clientID"), ""))
				}
				if len(p.AzureDNS.SubscriptionID) == 0 {
					el = append(el, field.Required(fldPath.Child("azuredns", "subscriptionID"), ""))
				}
				if len(p.AzureDNS.TenantID) == 0 {
					el = append(el, field.Required(fldPath.Child("azuredns", "tenantID"), ""))
				}
				if len(p.AzureDNS.ResourceGroupName) == 0 {
					el = append(el, field.Required(fldPath.Child("azuredns", "resourceGroupName"), ""))
				}
			}
		}
		if p.CloudDNS != nil {
			if numProviders > 0 {
				el = append(el, field.Forbidden(fldPath.Child("clouddns"), "may not specify more than one provider type"))
			} else {
				numProviders++
				// if either of serviceAccount.name or serviceAccount.key is set, we
				// validate the entire secret key selector
				if p.CloudDNS.ServiceAccount.Name != "" || p.CloudDNS.ServiceAccount.Key != "" {
					el = append(el, ValidateSecretKeySelector(&p.CloudDNS.ServiceAccount, fldPath.Child("clouddns", "serviceAccountSecretRef"))...)
				}
				if len(p.CloudDNS.Project) == 0 {
					el = append(el, field.Required(fldPath.Child("clouddns", "project"), ""))
				}
			}
		}
		if p.Cloudflare != nil {
			if numProviders > 0 {
				el = append(el, field.Forbidden(fldPath.Child("cloudflare"), "may not specify more than one provider type"))
			} else {
				numProviders++
				el = append(el, ValidateSecretKeySelector(&p.Cloudflare.APIKey, fldPath.Child("cloudflare", "apiKeySecretRef"))...)
				if len(p.Cloudflare.Email) == 0 {
					el = append(el, field.Required(fldPath.Child("cloudflare", "email"), ""))
				}
			}
		}
		if p.Route53 != nil {
			if numProviders > 0 {
				el = append(el, field.Forbidden(fldPath.Child("route53"), "may not specify more than one provider type"))
			} else {
				numProviders++
				// region is the only required field for route53 as ambient credentials can be used instead
				if len(p.Route53.Region) == 0 {
					el = append(el, field.Required(fldPath.Child("route53", "region"), ""))
				}
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
			if numProviders > 0 {
				el = append(el, field.Forbidden(fldPath.Child("digitalocean"), "may not specify more than one provider type"))
			} else {
				numProviders++
				el = append(el, ValidateSecretKeySelector(&p.DigitalOcean.Token, fldPath.Child("digitalocean", "tokenSecretRef"))...)
			}
		}
		if p.RFC2136 != nil {
			if numProviders > 0 {
				el = append(el, field.Forbidden(fldPath.Child("rfc2136"), "may not specify more than one provider type"))
			} else {
				numProviders++
				// Nameserver is the only required field for RFC2136
				if len(p.RFC2136.Nameserver) == 0 {
					el = append(el, field.Required(fldPath.Child("rfc2136", "nameserver"), ""))
				} else {
					if _, err := rfc2136.ValidNameserver(p.RFC2136.Nameserver); err != nil {
						el = append(el, field.Invalid(fldPath.Child("rfc2136", "nameserver"), "", "Nameserver invalid. Check the documentation for details."))
					}
				}
				if len(p.RFC2136.TSIGAlgorithm) > 0 {
					present := false
					for _, b := range rfc2136.GetSupportedAlgorithms() {
						if b == strings.ToUpper(p.RFC2136.TSIGAlgorithm) {
							present = true
						}
					}
					if !present {
						el = append(el, field.NotSupported(fldPath.Child("rfc2136", "tsigAlgorithm"), "", rfc2136.GetSupportedAlgorithms()))
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
		}
		if numProviders == 0 {
			el = append(el, field.Required(fldPath, "at least one provider must be configured"))
		}
	}
	return el
}

func ValidateSecretKeySelector(sks *v1alpha1.SecretKeySelector, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if sks.Name == "" {
		el = append(el, field.Required(fldPath.Child("name"), "secret name is required"))
	}
	if sks.Key == "" {
		el = append(el, field.Required(fldPath.Child("key"), "secret key is required"))
	}
	return el
}
