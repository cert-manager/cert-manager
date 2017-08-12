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

package certmanager

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Issuer struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   IssuerSpec
	Status IssuerStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IssuerList is a list of Issuers
type IssuerList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []Issuer
}

type IssuerSpec struct {
	ACME *ACMEIssuer
}

type IssuerStatus struct {
	Ready bool
	ACME  *ACMEIssuerStatus
}

type ACMEIssuerStatus struct {
	// URI is the unique account identifier, which can also be used to retrieve
	// account details from the CA
	URI string
}

type ACMEIssuer struct {
	// Email is the email for this account
	Email string
	// Server is the ACME server URL
	Server string
	// PrivateKey is the name of a secret containing the private key for this
	// user account.
	PrivateKey string
	// DNS-01 config
	DNS01 *ACMEIssuerDNS01Config
}

// ACMEIssuerDNS01Config is a structure containing the ACME DNS configuration
// option. One and only one of the fields within it should be set, when the
// ACME challenge type is set to dns-01
type ACMEIssuerDNS01Config struct {
	Providers []ACMEIssuerDNS01Provider
}

type ACMEIssuerDNS01Provider struct {
	Name string

	CloudDNS   *ACMEIssuerDNS01ProviderCloudDNS
	Cloudflare *ACMEIssuerDNS01ProviderCloudflare
	Route53    *ACMEIssuerDNS01ProviderRoute53
}

// ACMEIssuerDNS01ProviderCloudDNS is a structure containing the DNS
// configuration for Google Cloud DNS
type ACMEIssuerDNS01ProviderCloudDNS struct {
	ServiceAccount SecretKeySelector
	Project        string
}

// ACMEIssuerDNS01ProviderCloudflare is a structure containing the DNS
// configuration for Cloudflare
type ACMEIssuerDNS01ProviderCloudflare struct {
	Email  string
	APIKey SecretKeySelector
}

// ACMEIssuerDNS01ProviderRoute53 is a structure containing the Route 53
// configuration for AWS
type ACMEIssuerDNS01ProviderRoute53 struct {
	AccessKeyID     string
	SecretAccessKey SecretKeySelector
	// these following parameters are optional
	HostedZoneID string
	Region       string
}

// +genclient=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Certificate is a type to represent a Certificate from ACME
type Certificate struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   CertificateSpec
	Status CertificateStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CertificateList is a list of certificates
type CertificateList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []Certificate
}

// CertificateSpec defines the desired state of Certificate
type CertificateSpec struct {
	// Domains is a list of domains to obtain a certificate for
	Domains []string
	// SecretName is the name of the secret resource to store this secret in
	SecretName string
	// Issuer is the name of the issuer resource to use to obtain this
	// certificate
	Issuer string

	ACME *ACMECertificateConfig
}

// ACMEConfig contains the configuration for the ACME certificate provider
type ACMECertificateConfig struct {
	Config []ACMECertificateDomainConfig
}

type ACMECertificateDomainConfig struct {
	Domains []string
	HTTP01  *ACMECertificateHTTP01Config
	DNS01   *ACMECertificateDNS01Config
}

type ACMECertificateHTTP01Config struct {
	Ingress      string
	IngressClass *string
}

type ACMECertificateDNS01Config struct {
	Provider string
}

// CertificateStatus defines the observed state of Certificate
type CertificateStatus struct {
	ACME *CertificateACMEStatus
}

// CertificateACMEStatus holds the status for an ACME issuer
type CertificateACMEStatus struct {
	Authorizations []ACMEDomainAuthorization
}

// ACMEDomainAuthorization holds information about an ACME issuers domain
// authorization
type ACMEDomainAuthorization struct {
	Domain string
	URI    string
}

type LocalObjectReference struct {
	// Name of the referent.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
	// TODO: Add other useful fields. apiVersion, kind, uid?
	Name string
}

type SecretKeySelector struct {
	// The name of the secret in the pod's namespace to select from.
	LocalObjectReference
	// The key of the secret to select from.  Must be a valid secret key.
	Key string
}
