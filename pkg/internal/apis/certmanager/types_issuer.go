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

package certmanager

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/jetstack/cert-manager/pkg/internal/apis/acme"
	cmmeta "github.com/jetstack/cert-manager/pkg/internal/apis/meta"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

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

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

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
	// +optional
	ACME *cmacme.ACMEIssuer `json:"acme,omitempty"`

	// +optional
	CA *CAIssuer `json:"ca,omitempty"`

	// +optional
	Vault *VaultIssuer `json:"vault,omitempty"`

	// +optional
	SelfSigned *SelfSignedIssuer `json:"selfSigned,omitempty"`

	// +optional
	Venafi *VenafiIssuer `json:"venafi,omitempty"`
}

// VenafiIssuer describes issuer configuration details for Venafi Cloud.
type VenafiIssuer struct {
	// Zone is the Venafi Policy Zone to use for this issuer.
	// All requests made to the Venafi platform will be restricted by the named
	// zone policy.
	// This field is required.
	Zone string `json:"zone"`

	// TPP specifies Trust Protection Platform configuration settings.
	// Only one of TPP or Cloud may be specified.
	// +optional
	TPP *VenafiTPP `json:"tpp,omitempty"`

	// Cloud specifies the Venafi cloud configuration settings.
	// Only one of TPP or Cloud may be specified.
	// +optional
	Cloud *VenafiCloud `json:"cloud,omitempty"`
}

// VenafiTPP defines connection configuration details for a Venafi TPP instance
type VenafiTPP struct {
	// URL is the base URL for the Venafi TPP instance
	URL string `json:"url"`

	// CredentialsRef is a reference to a Secret containing the username and
	// password for the TPP server.
	// The secret must contain two keys, 'username' and 'password'.
	CredentialsRef cmmeta.LocalObjectReference `json:"credentialsRef"`

	// CABundle is a PEM encoded TLS certifiate to use to verify connections to
	// the TPP instance.
	// If specified, system roots will not be used and the issuing CA for the
	// TPP instance must be verifiable using the provided root.
	// If not specified, the connection will be verified using the cert-manager
	// system root certificates.
	// +optional
	CABundle []byte `json:"caBundle,omitempty"`
}

// VenafiCloud defines connection configuration details for Venafi Cloud
type VenafiCloud struct {
	// URL is the base URL for Venafi Cloud
	URL string `json:"url"`

	// APITokenSecretRef is a secret key selector for the Venafi Cloud API token.
	APITokenSecretRef cmmeta.SecretKeySelector `json:"apiTokenSecretRef"`
}

type SelfSignedIssuer struct{}

type VaultIssuer struct {
	// Vault authentication
	Auth VaultAuth `json:"auth"`

	// Server is the vault connection address
	Server string `json:"server"`

	// Vault URL path to the certificate role
	Path string `json:"path"`

	// Base64 encoded CA bundle to validate Vault server certificate. Only used
	// if the Server URL is using HTTPS protocol. This parameter is ignored for
	// plain HTTP protocol connection. If not set the system root certificates
	// are used to validate the TLS connection.
	// +optional
	CABundle []byte `json:"caBundle,omitempty"`
}

// Vault authentication  can be configured:
// - With a secret containing a token. Cert-manager is using this token as-is.
// - With a secret containing a AppRole. This AppRole is used to authenticate to
//   Vault and retrieve a token.
// - With a secret containing a Kubernetes ServiceAccount JWT. This JWT is used
//   to authenticate with Vault and retrieve a token.
type VaultAuth struct {
	// This Secret contains the Vault token key
	// +optional
	TokenSecretRef *cmmeta.SecretKeySelector `json:"tokenSecretRef,omitempty"`

	// This Secret contains a AppRole and Secret
	// +optional
	AppRole *VaultAppRole `json:"appRole,omitempty"`

	// This contains a Role and Secret with a ServiceAccount token to
	// authenticate with vault.
	// +optional
	Kubernetes *VaultKubernetesAuth `json:"kubernetes,omitempty"`
}

// Authenticate against Vault using an AppRole that is stored in a Secret.
type VaultAppRole struct {
	// Where the authentication path is mounted in Vault.
	Path string `json:"path"`

	RoleId    string                   `json:"roleId"`
	SecretRef cmmeta.SecretKeySelector `json:"secretRef"`
}

// Authenticate against Vault using a Kubernetes ServiceAccount token stored in
// a Secret.
type VaultKubernetesAuth struct {
	// The value here will be used as part of the path used when authenticating
	// with vault, for example if you set a value of "foo", the path used will be
	// `/v1/auth/foo/login`. If unspecified, the default value "kubernetes" will
	// be used.
	// +optional
	Path string `json:"mountPath,omitempty"`

	// The required Secret field containing a Kubernetes ServiceAccount JWT used
	// for authenticating with Vault. Use of 'ambient credentials' is not
	// supported.
	SecretRef cmmeta.SecretKeySelector `json:"secretRef"`

	// A required field containing the Vault Role to assume. A Role binds a
	// Kubernetes ServiceAccount with a set of Vault policies.
	Role string `json:"role"`
}

type CAIssuer struct {
	// SecretName is the name of the secret used to sign Certificates issued
	// by this Issuer.
	SecretName string `json:"secretName"`
}

// IssuerStatus contains status information about an Issuer
type IssuerStatus struct {
	// +optional
	Conditions []IssuerCondition `json:"conditions,omitempty"`

	// +optional
	ACME *cmacme.ACMEIssuerStatus `json:"acme,omitempty"`
}

// IssuerCondition contains condition information for an Issuer.
type IssuerCondition struct {
	// Type of the condition, currently ('Ready').
	Type IssuerConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	Status cmmeta.ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`
}

// IssuerConditionType represents an Issuer condition value.
type IssuerConditionType string

const (
	// IssuerConditionReady represents the fact that a given Issuer condition
	// is in ready state.
	IssuerConditionReady IssuerConditionType = "Ready"
)
