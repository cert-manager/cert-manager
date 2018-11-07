/*
Copyright 2018 The Jetstack cert-manager contributors.

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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ConfigList is a list of Configs.
type ConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Config `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Config is a cert-manager resource that captures configuration information to
// be used for running the cert-manager controller.
type Config struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	// EnabledControllers is a list of all enabled controllers.
	// If empty, all controllers will be enabled.
	EnabledControllers []string `json:"enabledControllers,omitempty"`

	// IssuerOptions configures global options for all issuers
	IssuerOptions IssuerOptions `json:"issuers"`

	// ACMEOptions configures global parameters for the ACME Issuer
	ACMEOptions ACMEOptions `json:"acme"`

	// IngressShimOptions configures the ingress-shim controller
	IngressShimOptions IngressShimOptions `json:"ingressShim"`
}

// IssuerOptions configures global options for all issuers
type IssuerOptions struct {
	// ClusterResourceNamespace is the namespace to store resources created by
	// non-namespaced resources (e.g. ClusterIssuer) in.
	// If not set, defaults to the namespace that the cert-manager pod is
	// running in.
	ClusterResourceNamespace string `json:"clusterResourceNamespace"`

	// AmbientCredentials contains options for configuration the use of ambient
	// credentials.
	AmbientCredentials AmbientCredentials `json:"ambientCredentials"`

	// RenewBeforeExpiryDuration is the default 'renew before expiry' time for
	// Certificates.
	// Once a certificate is within this duration until expiry, a new
	// Certificate will be attempted to be issued.
	RenewBeforeExpiryDuration *metav1.Duration `json:"renewBeforeExpiryDuration,omitempty"`
}

// AmbientCredentials configures the use of ambient credentials by cert-manager
type AmbientCredentials struct {
	// ClusterIssuers controls whether a cluster issuer should utilise ambient
	// credentials, such as those from metadata services, to construct clients.
	ClusterIssuers bool `json:"clusterIssuers"`

	// Issuers controls whether an issuer should pick up ambient credentials,
	// such as those from metadata services, to construct clients.
	Issuers bool `json:"issuers"`
}

// ACMEOptions configures global parameters for the ACME Issuer
type ACMEOptions struct {
	// HTTP01 challenge provider options
	HTTP01 HTTP01Options `json:"http01"`

	// DNS01 challenge provider options
	DNS01 DNS01Options `json:"dns01"`
}

// HTTP01Options configures the ACME HTTP01 solver
type HTTP01Options struct {
	// SolverImage is the image to use for solving ACME HTTP01 challenges
	SolverImage string `json:"solverImage"`

	SolveResources corev1.ResourceRequirements `json:"solverResources"`
}

// DNS01Options configures the ACME DNS01 solver
type DNS01Options struct {
	// Nameservers is a list of nameservers to use when performing self-checks
	// for ACME DNS01 validations.
	Nameservers []string `json:"nameservers,omitempty"`
}

// IngressShimOptions configures the ingress-shim controller
type IngressShimOptions struct {
	// Default issuer/certificates details consumed by ingress-shim
	DefaultIssuerKind                  string   `json:"defaultIssuerKind"`
	DefaultIssuerName                  string   `json:"defaultIssuerName"`
	DefaultACMEIssuerChallengeType     string   `json:"defaultACMEIssuerChallengeType"`
	DefaultACMEIssuerDNS01ProviderName string   `json:"defaultACMEIssuerDNS01ProviderName"`
	DefaultAutoCertificateAnnotations  []string `json:"defaultAutoCertificateAnnotations,omitempty"`
}
