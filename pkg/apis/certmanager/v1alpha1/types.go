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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	AltNamesAnnotationKey   = "certmanager.k8s.io/alt-names"
	CommonNameAnnotationKey = "certmanager.k8s.io/common-name"
	IssuerNameAnnotationKey = "certmanager.k8s.io/issuer-name"
	IssuerKindAnnotationKey = "certmanager.k8s.io/issuer-kind"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=clusterissuers

type ClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterIssuerList is a list of Issuers
type ClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ClusterIssuer `json:"items"`
}

// +genclient
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
	IssuerConfig `json:",inline"`
}

type IssuerConfig struct {
	ACME  *ACMEIssuer  `json:"acme,omitempty"`
	CA    *CAIssuer    `json:"ca,omitempty"`
	Vault *VaultIssuer `json:"vault,omitempty"`
}

type VaultIssuer struct {
	// Vault authentication
	Auth VaultAuth `json:"auth"`
	// Server is the vault connection address
	Server string `json:"server"`
	// Vault URL path to the certificate role
	Path string `json:"path"`
}

// Vault authentication  can be configured:
// - With a secret containing a token. Cert-manager is using this token as-is.
// - With a secret containing a AppRole. This AppRole is used to authenticate to
//   Vault and retrieve a token.
type VaultAuth struct {
	// This Secret contains the Vault token key
	TokenSecretRef SecretKeySelector `json:"tokenSecretRef,omitempty"`
	// This Secret contains a AppRole and Secret
	AppRole VaultAppRole `json:"appRole,omitempty"`
}

type VaultAppRole struct {
	RoleId    string            `json:"roleId"`
	SecretRef SecretKeySelector `json:"secretRef"`
}

type CAIssuer struct {
	// SecretName is the name of the secret used to sign Certificates issued
	// by this Issuer.
	SecretName string `json:"secretName"`
}

// ACMEIssuer contains the specification for an ACME issuer
type ACMEIssuer struct {
	// Email is the email for this account
	Email string `json:"email"`
	// Server is the ACME server URL
	Server string `json:"server"`
	// If true, skip verifying the ACME server TLS certificate
	SkipTLSVerify bool `json:"skipTLSVerify,omitempty"`
	// PrivateKey is the name of a secret containing the private key for this
	// user account.
	PrivateKey SecretKeySelector `json:"privateKeySecretRef"`
	// HTTP01 config
	HTTP01 *ACMEIssuerHTTP01Config `json:"http01,omitempty"`
	// DNS-01 config
	DNS01 *ACMEIssuerDNS01Config `json:"dns01,omitempty"`
}

type ACMEIssuerHTTP01Config struct {
}

// ACMEIssuerDNS01Config is a structure containing the ACME DNS configuration
// options
type ACMEIssuerDNS01Config struct {
	Providers []ACMEIssuerDNS01Provider `json:"providers"`
}

type ACMEIssuerDNS01Provider struct {
	Name string `json:"name"`

	Akamai     *ACMEIssuerDNS01ProviderAkamai     `json:"akamai,omitempty"`
	CloudDNS   *ACMEIssuerDNS01ProviderCloudDNS   `json:"clouddns,omitempty"`
	Cloudflare *ACMEIssuerDNS01ProviderCloudflare `json:"cloudflare,omitempty"`
	Route53    *ACMEIssuerDNS01ProviderRoute53    `json:"route53,omitempty"`
	AzureDNS   *ACMEIssuerDNS01ProviderAzureDNS   `json:"azuredns,omitempty"`
}

// ACMEIssuerDNS01ProviderAkamai is a structure containing the DNS
// configuration for Akamai DNS—Zone Record Management API
type ACMEIssuerDNS01ProviderAkamai struct {
	ServiceConsumerDomain string            `json:"serviceConsumerDomain"`
	ClientToken           SecretKeySelector `json:"clientTokenSecretRef"`
	ClientSecret          SecretKeySelector `json:"clientSecretSecretRef"`
	AccessToken           SecretKeySelector `json:"accessTokenSecretRef"`
}

// ACMEIssuerDNS01ProviderCloudDNS is a structure containing the DNS
// configuration for Google Cloud DNS
type ACMEIssuerDNS01ProviderCloudDNS struct {
	ServiceAccount SecretKeySelector `json:"serviceAccountSecretRef"`
	Project        string            `json:"project"`
}

// ACMEIssuerDNS01ProviderCloudflare is a structure containing the DNS
// configuration for Cloudflare
type ACMEIssuerDNS01ProviderCloudflare struct {
	Email  string            `json:"email"`
	APIKey SecretKeySelector `json:"apiKeySecretRef"`
}

// ACMEIssuerDNS01ProviderRoute53 is a structure containing the Route 53
// configuration for AWS
type ACMEIssuerDNS01ProviderRoute53 struct {
	AccessKeyID     string            `json:"accessKeyID"`
	SecretAccessKey SecretKeySelector `json:"secretAccessKeySecretRef"`
	HostedZoneID    string            `json:"hostedZoneID"`
	Region          string            `json:"region"`
}

// ACMEIssuerDNS01ProviderAzureDNS is a structure containing the
// configuration for Azure DNS
type ACMEIssuerDNS01ProviderAzureDNS struct {
	ClientID          string            `json:"clientID"`
	ClientSecret      SecretKeySelector `json:"clientSecretSecretRef"`
	SubscriptionID    string            `json:"subscriptionID"`
	TenantID          string            `json:"tenantID"`
	ResourceGroupName string            `json:"resourceGroupName"`

	// + optional
	HostedZoneName string `json:"hostedZoneName"`
}

// IssuerStatus contains status information about an Issuer
type IssuerStatus struct {
	Conditions []IssuerCondition `json:"conditions"`
	ACME       *ACMEIssuerStatus `json:"acme,omitempty"`
}

// IssuerCondition contains condition information for an Issuer.
type IssuerCondition struct {
	// Type of the condition, currently ('Ready').
	Type IssuerConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	Status ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	LastTransitionTime metav1.Time `json:"lastTransitionTime"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	Reason string `json:"reason"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	Message string `json:"message"`
}

// IssuerConditionType represents an Issuer condition value.
type IssuerConditionType string

const (
	// IssuerConditionReady represents the fact that a given Issuer condition
	// is in ready state.
	IssuerConditionReady IssuerConditionType = "Ready"
)

// ConditionStatus represents a condition's status.
type ConditionStatus string

// These are valid condition statuses. "ConditionTrue" means a resource is in
// the condition; "ConditionFalse" means a resource is not in the condition;
// "ConditionUnknown" means kubernetes can't decide if a resource is in the
// condition or not. In the future, we could add other intermediate
// conditions, e.g. ConditionDegraded.
const (
	// ConditionTrue represents the fact that a given condition is true
	ConditionTrue ConditionStatus = "True"

	// ConditionFalse represents the fact that a given condition is false
	ConditionFalse ConditionStatus = "False"

	// ConditionUnknown represents the fact that a given condition is unknown
	ConditionUnknown ConditionStatus = "Unknown"
)

type ACMEIssuerStatus struct {
	// URI is the unique account identifier, which can also be used to retrieve
	// account details from the CA
	URI string `json:"uri"`
}

// +genclient
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
	// CommonName is a common name to be used on the Certificate
	CommonName string `json:"commonName"`
	// DNSNames is a list of subject alt names to be used on the Certificate
	DNSNames []string `json:"dnsNames"`
	// SecretName is the name of the secret resource to store this secret in
	SecretName string `json:"secretName"`
	// IssuerRef is a reference to the issuer for this certificate. If the
	// namespace field is not set, it is assumed to be in the same namespace
	// as the certificate. If the namespace field is set to the empty value "",
	// a ClusterIssuer of the given name will be used. Any other value is
	// invalid.
	IssuerRef ObjectReference `json:"issuerRef"`

	ACME *ACMECertificateConfig `json:"acme,omitempty"`
}

// ACMEConfig contains the configuration for the ACME certificate provider
type ACMECertificateConfig struct {
	Config []ACMECertificateDomainConfig `json:"config"`
}

type ACMECertificateDomainConfig struct {
	Domains          []string `json:"domains"`
	ACMESolverConfig `json:",inline"`
}

type ACMESolverConfig struct {
	HTTP01 *ACMECertificateHTTP01Config `json:"http01,omitempty"`
	DNS01  *ACMECertificateDNS01Config  `json:"dns01,omitempty"`
}

type ACMECertificateHTTP01Config struct {
	Ingress      string  `json:"ingress"`
	IngressClass *string `json:"ingressClass,omitempty"`
}

type ACMECertificateDNS01Config struct {
	Provider string `json:"provider"`
}

// CertificateStatus defines the observed state of Certificate
type CertificateStatus struct {
	Conditions []CertificateCondition `json:"conditions,omitempty"`
	ACME       *CertificateACMEStatus `json:"acme,omitempty"`
}

// CertificateCondition contains condition information for an Certificate.
type CertificateCondition struct {
	// Type of the condition, currently ('Ready').
	Type CertificateConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	Status ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	LastTransitionTime metav1.Time `json:"lastTransitionTime"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	Reason string `json:"reason"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	Message string `json:"message"`
}

// CertificateConditionType represents an Certificate condition value.
type CertificateConditionType string

const (
	// CertificateConditionReady represents the fact that a given Certificate condition
	// is in ready state.
	CertificateConditionReady CertificateConditionType = "Ready"

	// CertificateConditionValidationFailed is used to indicate whether a
	// validation for a Certificate has failed.
	// This is currently used by the ACME issuer to track when the last
	// validation was attempted.
	CertificateConditionValidationFailed CertificateConditionType = "ValidateFailed"
)

// CertificateACMEStatus holds the status for an ACME issuer
type CertificateACMEStatus struct {
	// Order contains details about the current in-progress ACME Order.
	Order ACMEOrderStatus `json:"order,omitempty"`
}

type ACMEOrderStatus struct {
	// The URL that can be used to get information about the ACME order.
	URL        string               `json:"url"`
	Challenges []ACMEOrderChallenge `json:"challenges,omitempty"`
}

type ACMEOrderChallenge struct {
	// The URL that can be used to get information about the ACME challenge.
	URL string `json:"url"`

	// The URL that can be used to get information about the ACME authorization
	// associated with the challenge.
	AuthzURL string `json:"authzURL"`

	// Type of ACME challenge
	// Either http-01 or dns-01
	Type string `json:"type"`

	// Domain this challenge corresponds to
	Domain string `json:"domain"`

	// Challenge token for this challenge
	Token string `json:"token"`

	// Challenge key for this challenge
	Key string `json:"key"`

	// Set to true if this challenge is for a wildcard domain
	Wildcard bool `json:"wildcard"`

	// Configuration used to present this challenge
	ACMESolverConfig `json:",inline"`
}

type LocalObjectReference struct {
	// Name of the referent.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
	// TODO: Add other useful fields. apiVersion, kind, uid?
	Name string `json:"name,omitempty"`
}

// ObjectReference is a reference to an object. If the namespace field is set,
// it is assumed to be in a namespace
type ObjectReference struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

const (
	ClusterIssuerKind = "ClusterIssuer"
	IssuerKind        = "Issuer"
)

type SecretKeySelector struct {
	// The name of the secret in the pod's namespace to select from.
	LocalObjectReference `json:",inline" protobuf:"bytes,1,opt,name=localObjectReference"`
	// The key of the secret to select from.  Must be a valid secret key.
	Key string `json:"key" protobuf:"bytes,2,opt,name=key"`
}
