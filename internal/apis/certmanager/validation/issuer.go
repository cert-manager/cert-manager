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

package validation

import (
	"crypto/x509"
	"fmt"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmacme "github.com/cert-manager/cert-manager/internal/apis/acme"
	"github.com/cert-manager/cert-manager/internal/apis/certmanager"
	"github.com/cert-manager/cert-manager/internal/apis/certmanager/validation/util"
	cmmeta "github.com/cert-manager/cert-manager/internal/apis/meta"
)

// Validation functions for cert-manager Issuer types.

func ValidateIssuer(a *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, []string) {
	iss := obj.(*certmanager.Issuer)
	allErrs, warnings := ValidateIssuerSpec(&iss.Spec, field.NewPath("spec"))
	return allErrs, warnings
}

func ValidateUpdateIssuer(a *admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (field.ErrorList, []string) {
	iss := obj.(*certmanager.Issuer)
	allErrs, warnings := ValidateIssuerSpec(&iss.Spec, field.NewPath("spec"))
	// Admission request should never be nil
	return allErrs, warnings
}

func ValidateIssuerSpec(iss *certmanager.IssuerSpec, fldPath *field.Path) (field.ErrorList, []string) {
	return ValidateIssuerConfig(&iss.IssuerConfig, fldPath)
}

func ValidateIssuerConfig(iss *certmanager.IssuerConfig, fldPath *field.Path) (field.ErrorList, []string) {
	var warnings []string
	numConfigs := 0
	el := field.ErrorList{}
	if iss.ACME != nil {
		if numConfigs > 0 {
			el = append(el, field.Forbidden(fldPath.Child("acme"), "may not specify more than one issuer type"))
		} else {
			numConfigs++
			e, w := ValidateACMEIssuerConfig(iss.ACME, fldPath.Child("acme"))
			el, warnings = append(el, e...), append(warnings, w...)
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

	return el, warnings
}

func ValidateACMEIssuerConfig(iss *cmacme.ACMEIssuer, fldPath *field.Path) (field.ErrorList, []string) {
	var warnings []string

	el := field.ErrorList{}

	if len(iss.CABundle) > 0 && iss.SkipTLSVerify {
		el = append(el, field.Invalid(fldPath.Child("caBundle"), "", "caBundle and skipTLSVerify are mutually exclusive and cannot both be set"))
		el = append(el, field.Invalid(fldPath.Child("skipTLSVerify"), iss.SkipTLSVerify, "caBundle and skipTLSVerify are mutually exclusive and cannot both be set"))
	}

	if len(iss.CABundle) > 0 {
		if err := validateCABundleNotEmpty(iss.CABundle); err != nil {
			el = append(el, field.Invalid(fldPath.Child("caBundle"), "", err.Error()))
		}
	}

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

		// nolint:staticcheck // SA1019 accessing the deprecated eab.KeyAlgorithm field is intentional here.
		if len(eab.KeyAlgorithm) != 0 {
			warnings = append(warnings, deprecatedACMEEABKeyAlgorithmField)
		}
	}

	for i, sol := range iss.Solvers {
		el = append(el, ValidateACMEIssuerChallengeSolverConfig(&sol, fldPath.Child("solvers").Index(i))...) // #nosec G601 -- False positive. See https://github.com/golang/go/discussions/56010
	}

	return el, warnings
}

func ValidateACMEIssuerChallengeSolverConfig(sol *cmacme.ACMEChallengeSolver, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	numProviders := 0
	if sol.HTTP01 != nil {
		numProviders++
		el = append(el, ValidateACMEIssuerChallengeSolverHTTP01Config(sol.HTTP01, fldPath.Child("http01"))...)
	}
	if sol.DNS01 != nil {
		if numProviders > 0 {
			el = append(el, field.Forbidden(fldPath, "may not specify more than one solver type in a single solver"))
		} else {
			numProviders++
			el = append(el, ValidateACMEChallengeSolverDNS01(sol.DNS01, fldPath.Child("dns01"))...)
		}
	}
	if numProviders == 0 {
		el = append(el, field.Required(fldPath, "no solver type configured"))
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
	if http01.GatewayHTTPRoute != nil {
		numDefined++
		el = append(el, ValidateACMEIssuerChallengeSolverHTTP01GatewayConfig(http01.GatewayHTTPRoute, fldPath.Child("gateway"))...)
	}
	if numDefined == 0 {
		el = append(el, field.Required(fldPath, "no HTTP01 solver type configured"))
	}
	if numDefined > 1 {
		el = append(el, field.Required(fldPath, "only 1 HTTP01 solver type may be configured"))
	}

	return el
}

func ValidateACMEIssuerChallengeSolverHTTP01IngressConfig(ingress *cmacme.ACMEChallengeSolverHTTP01Ingress, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	if ingress.Class != nil && ingress.IngressClassName != nil && len(ingress.Name) > 0 {
		el = append(el, field.Forbidden(fldPath, "only one of 'ingressClassName', 'name' or 'class' should be specified"))
	}

	// Since "class" used to be a free string, let's have a stricter validation
	// for "ingressClassName" since it is expected to be a valid resource name.
	// A notable example is "azure/application-gateway" that is a valid value
	// for "class" but not for "ingressClassName".
	if ingress.IngressClassName != nil {
		errs := validation.IsDNS1123Subdomain(*ingress.IngressClassName)
		if len(errs) > 0 {
			el = append(el, field.Invalid(fldPath.Child("ingressClassName"), *ingress.IngressClassName, "must be a valid IngressClass name: "+strings.Join(errs, ", ")))
		}
	}

	switch ingress.ServiceType {
	case "", corev1.ServiceTypeClusterIP, corev1.ServiceTypeNodePort:
	default:
		el = append(el, field.Invalid(fldPath.Child("serviceType"), ingress.ServiceType, `must be empty, "ClusterIP" or "NodePort"`))
	}

	return el
}

func ValidateACMEIssuerChallengeSolverHTTP01GatewayConfig(gateway *cmacme.ACMEChallengeSolverHTTP01GatewayHTTPRoute, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	switch gateway.ServiceType {
	case "", corev1.ServiceTypeClusterIP, corev1.ServiceTypeNodePort:
	default:
		el = append(el, field.Invalid(fldPath.Child("serviceType"), gateway.ServiceType, `must be empty, "ClusterIP" or "NodePort"`))
	}
	if len(gateway.ParentRefs) == 0 {
		el = append(el, field.Required(fldPath.Child("parentRefs"), `at least 1 parentRef is required`))
	}
	return el
}

func ValidateCAIssuerConfig(iss *certmanager.CAIssuer, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if len(iss.SecretName) == 0 {
		el = append(el, field.Required(fldPath.Child("secretName"), ""))
	}
	for i, ocspURL := range iss.OCSPServers {
		if ocspURL == "" {
			el = append(el, field.Invalid(fldPath.Child("ocspServer").Index(i), ocspURL, "must be a valid URL, e.g., http://ocsp.int-x3.letsencrypt.org"))
		}
	}
	for i, issuerURL := range iss.IssuingCertificateURLs {
		if issuerURL == "" {
			el = append(el, field.Invalid(fldPath.Child("issuingCertificateURLs").Index(i), issuerURL, "must be a valid URL"))
		}
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

	if len(iss.CABundle) > 0 {
		if err := validateCABundleNotEmpty(iss.CABundle); err != nil {
			el = append(el, field.Invalid(fldPath.Child("caBundle"), "<snip>", err.Error()))
		}
	}

	if len(iss.CABundle) > 0 && iss.CABundleSecretRef != nil {
		// We don't use iss.CABundle for the "value interface{}" argument to field.Invalid for caBundle
		// since printing the whole bundle verbatim won't help diagnose any issues
		el = append(el, field.Invalid(fldPath.Child("caBundle"), "<snip>", "specified caBundle and caBundleSecretRef cannot be used together"))
		el = append(el, field.Invalid(fldPath.Child("caBundleSecretRef"), iss.CABundleSecretRef.Name, "specified caBundleSecretRef and caBundle cannot be used together"))
	}

	if iss.ClientCertSecretRef != nil && iss.ClientKeySecretRef == nil {
		el = append(el, field.Invalid(fldPath.Child("clientKeySecretRef"), "<snip>", "clientKeySecretRef must be provided when defining the clientCertSecretRef"))
	} else if iss.ClientCertSecretRef == nil && iss.ClientKeySecretRef != nil {
		el = append(el, field.Invalid(fldPath.Child("clientCertSecretRef"), "<snip>", "clientCertSecretRef must be provided when defining the clientKeySecretRef"))
	}

	el = append(el, ValidateVaultIssuerAuth(&iss.Auth, fldPath.Child("auth"))...)

	return el
}

func ValidateVaultIssuerAuth(auth *certmanager.VaultAuth, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	unionCount := 0
	if auth.TokenSecretRef != nil {
		unionCount++
	}

	if auth.AppRole != nil {
		if auth.AppRole.RoleId == "" {
			el = append(el, field.Required(fldPath.Child("appRole", "roleId"), ""))
		}

		if auth.AppRole.SecretRef.Name == "" {
			el = append(el, field.Required(fldPath.Child("appRole", "secretRef", "name"), ""))
		}
		unionCount++
	}

	if auth.ClientCertificate != nil {
		unionCount++
	}

	if auth.Kubernetes != nil {
		unionCount++

		if auth.Kubernetes.Role == "" {
			el = append(el, field.Required(fldPath.Child("kubernetes", "role"), ""))
		}

		kubeCount := 0
		if len(auth.Kubernetes.SecretRef.Name) > 0 {
			kubeCount++
		}

		if auth.Kubernetes.ServiceAccountRef != nil {
			kubeCount++
			if len(auth.Kubernetes.ServiceAccountRef.Name) == 0 {
				el = append(el, field.Required(fldPath.Child("kubernetes", "serviceAccountRef", "name"), ""))
			}
		}

		if kubeCount == 0 {
			el = append(el, field.Required(fldPath.Child("kubernetes"), "please supply one of: secretRef, serviceAccountRef"))
		}
		if kubeCount > 1 {
			el = append(el, field.Forbidden(fldPath.Child("kubernetes"), "please supply one of: secretRef, serviceAccountRef"))
		}
	}

	if unionCount == 0 {
		el = append(el, field.Required(fldPath, "please supply one of: appRole, kubernetes, tokenSecretRef, clientCertificate"))
	}

	// Due to the fact that there has not been any "oneOf" validation on
	// tokenSecretRef, appRole, and kubernetes, people may already have created
	// Issuer resources in which they have set two of these fields instead of
	// one. To avoid breaking these manifests, we don't check that the user has
	// set a single field among these three. Instead, we documented in the API
	// that it is the first field that is set gets used.

	return el
}

func ValidateVenafiTPP(tpp *certmanager.VenafiTPP, fldPath *field.Path) (el field.ErrorList) {
	if tpp.URL == "" {
		el = append(el, field.Required(fldPath.Child("url"), ""))
	}

	// TODO: validate CABundle using validateCABundleNotEmpty

	// Validate only one of CABundle/CABundleSecretRef is passed
	el = append(el, validateVenafiTPPCABundleUnique(tpp, fldPath)...)

	return el
}

func validateVenafiTPPCABundleUnique(tpp *certmanager.VenafiTPP, fldPath *field.Path) (el field.ErrorList) {
	numCAs := 0
	if len(tpp.CABundle) > 0 {
		numCAs++
	}
	if tpp.CABundleSecretRef != nil {
		numCAs++
	}

	if numCAs > 1 {
		el = append(el, field.Forbidden(fldPath, "may not specify more than one of caBundle/caBundleSecretRef as TPP CA Bundle"))
	}

	return el
}

func ValidateVenafiCloud(c *certmanager.VenafiCloud, fldPath *field.Path) (el field.ErrorList) {
	return el
}

func ValidateVenafiIssuerConfig(iss *certmanager.VenafiIssuer, fldPath *field.Path) (el field.ErrorList) {
	if iss.Zone == "" {
		el = append(el, field.Required(fldPath.Child("zone"), ""))
	}
	unionCount := 0
	if iss.TPP != nil {
		unionCount++
		el = append(el, ValidateVenafiTPP(iss.TPP, fldPath.Child("tpp"))...)
	}
	if iss.Cloud != nil {
		unionCount++
		el = append(el, ValidateVenafiCloud(iss.Cloud, fldPath.Child("cloud"))...)
	}

	if unionCount == 0 {
		el = append(el, field.Required(fldPath, "please supply one of: tpp, cloud"))
	}
	if unionCount > 1 {
		el = append(el, field.Forbidden(fldPath, "please supply one of: tpp, cloud"))
	}

	return el
}

// This list must be kept in sync with pkg/issuer/acme/dns/rfc2136/rfc2136.go
var supportedTSIGAlgorithms = []string{
	"HMACMD5",
	"HMACSHA1",
	"HMACSHA256",
	"HMACSHA512",
}

func ValidateACMEChallengeSolverDNS01(p *cmacme.ACMEChallengeSolverDNS01, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	// allow empty values for now, until we have a MutatingWebhook to apply
	// default values to fields.
	if len(p.CNAMEStrategy) > 0 {
		switch p.CNAMEStrategy {
		case cmacme.NoneStrategy:
		case cmacme.FollowStrategy:
		default:
			el = append(el, field.Invalid(fldPath.Child("cnameStrategy"), p.CNAMEStrategy, fmt.Sprintf("must be one of %q or %q", cmacme.NoneStrategy, cmacme.FollowStrategy)))
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
			el = append(el, field.Forbidden(fldPath.Child("azureDNS"), "may not specify more than one provider type"))
		} else {
			numProviders++
			// if ClientID or ClientSecret or TenantID are defined then all of ClientID, ClientSecret and tenantID must be defined
			// We check things separately because
			if len(p.AzureDNS.ClientID) > 0 || len(p.AzureDNS.TenantID) > 0 || p.AzureDNS.ClientSecret != nil {
				if len(p.AzureDNS.ClientID) == 0 {
					el = append(el, field.Required(fldPath.Child("azureDNS", "clientID"), ""))
				}
				if p.AzureDNS.ClientSecret == nil {
					el = append(el, field.Required(fldPath.Child("azureDNS", "clientSecretSecretRef"), ""))
				} else {
					el = append(el, ValidateSecretKeySelector(p.AzureDNS.ClientSecret, fldPath.Child("azureDNS", "clientSecretSecretRef"))...)
				}
				if len(p.AzureDNS.TenantID) == 0 {
					el = append(el, field.Required(fldPath.Child("azureDNS", "tenantID"), ""))
				}
				if p.AzureDNS.ManagedIdentity != nil {
					el = append(el, field.Forbidden(fldPath.Child("azureDNS", "managedIdentity"), "managed identity can not be used at the same time as clientID, clientSecretSecretRef or tenantID"))
				}
			} else if p.AzureDNS.ManagedIdentity != nil && len(p.AzureDNS.ManagedIdentity.ClientID) > 0 && len(p.AzureDNS.ManagedIdentity.ResourceID) > 0 {
				el = append(el, field.Forbidden(fldPath.Child("azureDNS", "managedIdentity"), "managedIdentityClientID and managedIdentityResourceID cannot both be specified"))
			}

			// SubscriptionID must always be defined
			if len(p.AzureDNS.SubscriptionID) == 0 {
				el = append(el, field.Required(fldPath.Child("azureDNS", "subscriptionID"), ""))
			}
			// ResourceGroupName must always be defined
			if len(p.AzureDNS.ResourceGroupName) == 0 {
				el = append(el, field.Required(fldPath.Child("azureDNS", "resourceGroupName"), ""))
			}
			switch p.AzureDNS.Environment {
			case "", cmacme.AzurePublicCloud, cmacme.AzureChinaCloud, cmacme.AzureGermanCloud, cmacme.AzureUSGovernmentCloud:
			default:
				el = append(el, field.Invalid(fldPath.Child("azureDNS", "environment"), p.AzureDNS.Environment,
					fmt.Sprintf("must be either empty or one of %s, %s, %s or %s", cmacme.AzurePublicCloud, cmacme.AzureChinaCloud, cmacme.AzureGermanCloud, cmacme.AzureUSGovernmentCloud)))
			}
		}
	}
	if p.CloudDNS != nil {
		if numProviders > 0 {
			el = append(el, field.Forbidden(fldPath.Child("cloudDNS"), "may not specify more than one provider type"))
		} else {
			numProviders++
			// if service account is not nil we validate the entire secret key
			// selector
			if p.CloudDNS.ServiceAccount != nil {
				el = append(el, ValidateSecretKeySelector(p.CloudDNS.ServiceAccount, fldPath.Child("cloudDNS", "serviceAccountSecretRef"))...)
			}
			if len(p.CloudDNS.Project) == 0 {
				el = append(el, field.Required(fldPath.Child("cloudDNS", "project"), ""))
			}
		}
	}
	if p.Cloudflare != nil {
		if numProviders > 0 {
			el = append(el, field.Forbidden(fldPath.Child("cloudflare"), "may not specify more than one provider type"))
		} else {
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
			if len(p.Cloudflare.Email) == 0 && p.Cloudflare.APIKey != nil {
				el = append(el, field.Required(fldPath.Child("cloudflare", "email"), ""))
			}
		}
	}
	if p.Route53 != nil {
		if numProviders > 0 {
			el = append(el, field.Forbidden(fldPath.Child("route53"), "may not specify more than one provider type"))
		} else {
			numProviders++
			// We don't include a validation here asserting that either the
			// AccessKeyID or SecretAccessKeyID must be specified, because it is
			// valid to use neither when using ambient credentials.
			if len(p.Route53.AccessKeyID) > 0 && p.Route53.SecretAccessKeyID != nil {
				el = append(el, field.Required(fldPath.Child("route53"), "accessKeyID and accessKeyIDSecretRef cannot both be specified"))
			}
			// if an accessKeyIDSecretRef is given, validate that it resolves to an actual secret
			if p.Route53.SecretAccessKeyID != nil {
				el = append(el, ValidateSecretKeySelector(p.Route53.SecretAccessKeyID, fldPath.Child("route53", "accessKeyIDSecretRef"))...)
			}
		}
	}
	if p.AcmeDNS != nil {
		numProviders++
		el = append(el, ValidateSecretKeySelector(&p.AcmeDNS.AccountSecret, fldPath.Child("acmeDNS", "accountSecretRef"))...)
		if len(p.AcmeDNS.Host) == 0 {
			el = append(el, field.Required(fldPath.Child("acmeDNS", "host"), ""))
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
				if _, err := util.ValidNameserver(p.RFC2136.Nameserver); err != nil {
					el = append(el, field.Invalid(fldPath.Child("rfc2136", "nameserver"), p.RFC2136.Nameserver, "nameserver must be set in the form host:port where host is an IPv4 address, an enclosed IPv6 address or a hostname and port is an optional port number."))
				}
			}
			if len(p.RFC2136.TSIGAlgorithm) > 0 {
				present := false
				for _, b := range supportedTSIGAlgorithms {
					if b == strings.ToUpper(p.RFC2136.TSIGAlgorithm) {
						present = true
					}
				}
				if !present {
					el = append(el, field.NotSupported(fldPath.Child("rfc2136", "tsigAlgorithm"), "", supportedTSIGAlgorithms))
				}
			}
			if len(p.RFC2136.TSIGKeyName) > 0 {
				el = append(el, ValidateSecretKeySelector(&p.RFC2136.TSIGSecret, fldPath.Child("rfc2136", "tsigSecretSecretRef"))...)
			}

			if len(ValidateSecretKeySelector(&p.RFC2136.TSIGSecret, fldPath.Child("rfc2136", "tsigSecretSecretRef"))) == 0 {
				if len(p.RFC2136.TSIGKeyName) == 0 {
					el = append(el, field.Required(fldPath.Child("rfc2136", "tsigKeyName"), ""))
				}

			}
		}
	}
	if p.Webhook != nil {
		if numProviders > 0 {
			el = append(el, field.Forbidden(fldPath.Child("webhook"), "may not specify more than one provider type"))
		} else {
			numProviders++
			if len(p.Webhook.SolverName) == 0 {
				el = append(el, field.Required(fldPath.Child("webhook", "solverName"), "solver name must be specified"))
			}
		}
	}
	if numProviders == 0 {
		el = append(el, field.Required(fldPath, "no DNS01 provider configured"))
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

// validateCABundleNotEmpty performs a soft check on the CA bundle to see if there's at least one
// valid CA certificate inside.
// This uses the standard library crypto/x509.CertPool.AppendCertsFromPEM function, which
// skips over invalid certificates rather than rejecting them.
func validateCABundleNotEmpty(bundle []byte) error {
	// TODO: Change this function to actually validate certificates so that invalid certs
	// are rejected or at least warned on.
	// For example, something like: https://github.com/cert-manager/trust-manager/blob/21c839ff1128990e049eaf23000a9a8d6716c89e/pkg/util/pem.go#L26-L81

	pool := x509.NewCertPool()

	ok := pool.AppendCertsFromPEM(bundle)
	if !ok {
		return fmt.Errorf("cert bundle didn't contain any valid certificates")
	}

	return nil
}
