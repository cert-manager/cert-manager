/*
Copyright 2017 The Kubernetes Authors.

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

package v1alpha1

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient=true
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=issuers

type Issuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IssuerList is a list of Issuers
type IssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Issuer `json:"items"`
}

// IssuerSpec is the specification of an Issuer. This includes any
// configuration required for the issuer.
type IssuerSpec struct {
	ACME *ACMEIssuer `json:"acme,omitempty"`
}

// IssuerStatus contains status information about an Issuer
type IssuerStatus struct {
	Ready bool `json:"ready"`
}

// ACMEIssuer contains the specification for an ACME issuer
type ACMEIssuer struct {
	// Email is the email for this account
	Email string `json:"email"`
	// Server is the ACME server URL
	Server string `json:"server"`
	// PrivateKey is the name of a secret containing the private key for this
	// user account.
	PrivateKey string `json:"privateKey"`
	// URI is the unique account identifier, which can also be used to retrieve
	// account details from the CA
	URI string `json:"uri"`
	// DNS-01 config
	DNS01 *ACMEIssuerDNS01Config `json:"dns-01"`
}

// ACMEIssuerDNS01Config is a structure containing the ACME DNS configuration
// option. One and only one of the fields within it should be set, when the
// ACME challenge type is set to dns-01
type ACMEIssuerDNS01Config struct {
	Providers []ACMEIssuerDNS01Provider `json:"providers"`
}

func (a *ACMEIssuerDNS01Config) Provider(name string) (*ACMEIssuerDNS01Provider, error) {
	for _, p := range a.Providers {
		if p.Name == name {
			return &(*&p), nil
		}
	}
	return nil, fmt.Errorf("provider '%s' not found", name)
}

type ACMEIssuerDNS01Provider struct {
	Name string `json:"name"`

	CloudDNS *ACMEIssuerDNS01ProviderCloudDNS `json:"clouddns"`
}

// ACMEIssuerDNS01ProviderCloudDNS is a structure containing the DNS
// configuration for Google Cloud DNS
type ACMEIssuerDNS01ProviderCloudDNS struct {
	ServiceAccount string `json:"serviceAccount"`
	Project        string `json:"project"`
}

// +genclient=true
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=certificates

// Certificate is a type to represent a Certificate from ACME
type Certificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateSpec   `json:"spec,omitempty"`
	Status CertificateStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CertificateList is a list of Certificates
type CertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Certificate `json:"items"`
}

// CertificateSpec defines the desired state of Certificate
type CertificateSpec struct {
	// Domains is a list of domains to obtain a certificate for
	Domains []string `json:"domains"`
	// Secret is the name of the secret resource to store this secret in
	SecretName string `json:"secretName"`
	// Issuer is the name of the issuer resource to use to obtain this
	// certificate
	Issuer string `json:"issuer"`

	ACME *ACMECertificateConfig `json:"acme"`
}

// ACMEConfig contains the configuration for the ACME certificate provider
type ACMECertificateConfig struct {
	Config []ACMECertificateDomainConfig `json:"config"`
}

func (a *ACMECertificateConfig) ConfigForDomain(domain string) ACMECertificateDomainConfig {
	for _, cfg := range a.Config {
		for _, d := range cfg.Domains {
			if d == domain {
				return cfg
			}
		}
	}
	return ACMECertificateDomainConfig{}
}

type ACMECertificateDomainConfig struct {
	Domains []string                     `json:"domains"`
	HTTP01  *ACMECertificateHTTP01Config `json:"http-01"`
	DNS01   *ACMECertificateDNS01Config  `json:"dns-01"`
}

type ACMECertificateHTTP01Config struct {
	Ingress      string  `json:"ingress"`
	IngressClass *string `json:"ingressClass"`
}

type ACMECertificateDNS01Config struct {
	Provider string `json:"provider"`
}

// CertificateStatus defines the observed state of Certificate
type CertificateStatus struct {
	ACME *CertificateACMEStatus `json:"acme"`
}

// CertificateACMEStatus holds the status for an ACME issuer
type CertificateACMEStatus struct {
	Authorizations []ACMEDomainAuthorization `json:"acme"`
}

func (c *CertificateACMEStatus) SaveAuthorization(a ACMEDomainAuthorization) {
	for i, auth := range c.Authorizations {
		if auth.Domain == a.Domain {
			c.Authorizations[i] = a
			return
		}
	}
	c.Authorizations = append(c.Authorizations, a)
}

// ACMEDomainAuthorization holds information about an ACME issuers domain
// authorization
type ACMEDomainAuthorization struct {
	Domain string `json:"domain"`
	URI    string `json:"uri"`
}
