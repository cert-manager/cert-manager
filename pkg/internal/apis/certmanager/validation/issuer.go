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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmacme "github.com/jetstack/cert-manager/pkg/internal/apis/acme"
	"github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
	"github.com/jetstack/cert-manager/pkg/internal/apis/certmanager/validation/util"
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

func ValidateACMEIssuerConfig(iss *cmacme.ACMEIssuer, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	for i, sol := range iss.Solvers {
		el = append(el, ValidateACMEIssuerChallengeSolverConfig(&sol, fldPath.Child("solvers").Index(i))...)
	}

	return el
}

func ValidateACMEIssuerChallengeSolverConfig(sol *cmacme.ACMEChallengeSolver, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	if sol.HTTP01 != nil {
		el = append(el, ValidateACMEIssuerChallengeSolverHTTP01Config(sol.HTTP01, fldPath.Child("http01"))...)
	}
	if sol.DNS01 != nil {
		if sol.HTTP01 != nil {
			el = append(el, field.Forbidden(fldPath, "may not specify more than one solver type in a single solver"))
		} else {
			el = append(el, ValidateACMEChallengeSolverDNS01(sol.DNS01, fldPath.Child("dns01"))...)
		}
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
	//TODO: make extended validation for fake\tpp\cloud modes
	return nil
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
	}
	if p.AzureDNS != nil {
		numProviders++
	}
	if p.CloudDNS != nil {
		numProviders++
	}
	if p.Cloudflare != nil {
		numProviders++
		if p.Cloudflare.APIKey != nil && p.Cloudflare.APIToken != nil {
			el = append(el, field.Forbidden(fldPath.Child("cloudflare"), "apiKeySecretRef and apiTokenSecretRef cannot both be specified"))
		}
		if p.Cloudflare.APIKey == nil && p.Cloudflare.APIToken == nil {
			el = append(el, field.Required(fldPath.Child("cloudflare"), "apiKeySecretRef or apiTokenSecretRef is required"))
		}
	}
	if p.Route53 != nil {
		numProviders++
	}
	if p.AcmeDNS != nil {
		numProviders++
	}

	if p.DigitalOcean != nil {
		numProviders++
	}
	if p.RFC2136 != nil {
		numProviders++
		// Nameserver is the only required field for RFC2136
		if _, err := util.ValidNameserver(p.RFC2136.Nameserver); err != nil {
			el = append(el, field.Invalid(fldPath.Child("rfc2136", "nameserver"), "", "Nameserver invalid. Check the documentation for details."))
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

		if len(p.RFC2136.TSIGSecret.Name) != 0 {
			if len(p.RFC2136.TSIGKeyName) == 0 {
				el = append(el, field.Required(fldPath.Child("rfc2136", "tsigKeyName"), ""))
			}
		}
	}
	if p.Webhook != nil {
		numProviders++
	}
	if numProviders == 0 {
		el = append(el, field.Required(fldPath, "no DNS01 provider configured"))
	}

	if numProviders > 1 {
		el = append(el, field.Forbidden(fldPath, "may not specify more than one provider type"))
	}

	return el
}
