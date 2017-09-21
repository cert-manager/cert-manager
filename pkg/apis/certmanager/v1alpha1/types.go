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
	ACME *ACMEIssuer `json:"acme,omitempty"`
	CA   *CAIssuer   `json:"ca,omitempty"`
}

type CAIssuer struct {
	SecretRef LocalObjectReference `json:"secretRef"`
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
	// DNS-01 config
	DNS01 *ACMEIssuerDNS01Config `json:"dns-01"`
}

// ACMEIssuerDNS01Config is a structure containing the ACME DNS configuration
// option. One and only one of the fields within it should be set, when the
// ACME challenge type is set to dns-01
type ACMEIssuerDNS01Config struct {
	Providers []ACMEIssuerDNS01Provider `json:"providers"`
}

type ACMEIssuerDNS01Provider struct {
	Name string `json:"name"`

	CloudDNS   *ACMEIssuerDNS01ProviderCloudDNS   `json:"clouddns,omitempty"`
	Cloudflare *ACMEIssuerDNS01ProviderCloudflare `json:"cloudflare,omitempty"`
	Route53    *ACMEIssuerDNS01ProviderRoute53    `json:"route53,omitempty"`
}

// ACMEIssuerDNS01ProviderCloudDNS is a structure containing the DNS
// configuration for Google Cloud DNS
type ACMEIssuerDNS01ProviderCloudDNS struct {
	ServiceAccount SecretKeySelector `json:"serviceAccount"`
	Project        string            `json:"project"`
}

// ACMEIssuerDNS01ProviderCloudflare is a structure containing the DNS
// configuration for Cloudflare
type ACMEIssuerDNS01ProviderCloudflare struct {
	Email  string            `json:"email"`
	APIKey SecretKeySelector `json:"apiKey"`
}

// ACMEIssuerDNS01ProviderRoute53 is a structure containing the Route 53
// configuration for AWS
type ACMEIssuerDNS01ProviderRoute53 struct {
	AccessKeyID     string            `json:"accessKeyID"`
	SecretAccessKey SecretKeySelector `json:"secretAccessKey"`
	HostedZoneID    string            `json:"hostedZoneID"`
	Region          string            `json:"region"`
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
	// Domains is a list of domains to obtain a certificate for
	Domains []string `json:"domains"`
	// Secret is the name of the secret resource to store this secret in
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
	Domains []string                     `json:"domains"`
	HTTP01  *ACMECertificateHTTP01Config `json:"http-01,omitempty"`
	DNS01   *ACMECertificateDNS01Config  `json:"dns-01,omitempty"`
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
	Conditions []CertificateCondition `json:"conditions"`
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
)

// CertificateACMEStatus holds the status for an ACME issuer
type CertificateACMEStatus struct {
	Authorizations []ACMEDomainAuthorization `json:"authorizations"`
}

// ACMEDomainAuthorization holds information about an ACME issuers domain
// authorization
type ACMEDomainAuthorization struct {
	Domain string `json:"domain"`
	URI    string `json:"uri"`
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
	Name      string  `json:"name,omitempty"`
	Namespace *string `json:"namespace,omitempty"`
}

type SecretKeySelector struct {
	// The name of the secret in the pod's namespace to select from.
	LocalObjectReference `json:",inline" protobuf:"bytes,1,opt,name=localObjectReference"`
	// The key of the secret to select from.  Must be a valid secret key.
	Key string `json:"key" protobuf:"bytes,2,opt,name=key"`
}
