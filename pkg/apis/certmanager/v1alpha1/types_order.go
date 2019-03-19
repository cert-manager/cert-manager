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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TODO: these types should be moved into their own API group once we have a loose
// coupling between ACME Issuers and their solver configurations (see: Solver proposal)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Order is a type to represent an Order with an ACME server
// +k8s:openapi-gen=true
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Issuer",type="string",JSONPath=".spec.issuerRef.name",description="",priority=1
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.reason",description="",priority=1
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="CreationTimestamp is a timestamp representing the server time when this object was created. It is not guaranteed to be set in happens-before order across separate operations. Clients may not set this value. It is represented in RFC3339 form and is in UTC."
// +kubebuilder:resource:path=orders
type Order struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   OrderSpec   `json:"spec"`
	Status OrderStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// OrderList is a list of Orders
type OrderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Order `json:"items"`
}

type OrderSpec struct {
	// Certificate signing request bytes in DER encoding.
	// This will be used when finalizing the order.
	// This field must be set on the order.
	CSR []byte `json:"csr"`

	// IssuerRef references a properly configured ACME-type Issuer which should
	// be used to create this Order.
	// If the Issuer does not exist, processing will be retried.
	// If the Issuer is not an 'ACME' Issuer, an error will be returned and the
	// Order will be marked as failed.
	IssuerRef ObjectReference `json:"issuerRef"`

	// CommonName is the common name as specified on the DER encoded CSR.
	// If CommonName is not specified, the first DNSName specified will be used
	// as the CommonName.
	// At least one of CommonName or a DNSNames must be set.
	// This field must match the corresponding field on the DER encoded CSR.
	// +optional
	CommonName string `json:"commonName,omitempty"`

	// DNSNames is a list of DNS names that should be included as part of the Order
	// validation process.
	// If CommonName is not specified, the first DNSName specified will be used
	// as the CommonName.
	// At least one of CommonName or a DNSNames must be set.
	// This field must match the corresponding field on the DER encoded CSR.
	// +optional
	DNSNames []string `json:"dnsNames,omitempty"`

	// Config specifies a mapping from DNS identifiers to how those identifiers
	// should be solved when performing ACME challenges.
	// A config entry must exist for each domain listed in DNSNames and CommonName.
	Config []DomainSolverConfig `json:"config"`
}

type OrderStatus struct {
	// URL of the Order.
	// This will initially be empty when the resource is first created.
	// The Order controller will populate this field when the Order is first processed.
	// This field will be immutable after it is initially set.
	// +optional
	URL string `json:"url,omitempty"`

	// FinalizeURL of the Order.
	// This is used to obtain certificates for this order once it has been completed.
	// +optional
	FinalizeURL string `json:"finalizeURL,omitempty"`

	// Certificate is a copy of the PEM encoded certificate for this Order.
	// This field will be populated after the order has been successfully
	// finalized with the ACME server, and the order has transitioned to the
	// 'valid' state.
	// +optional
	Certificate []byte `json:"certificate,omitempty"`

	// State contains the current state of this Order resource.
	// States 'success' and 'expired' are 'final'
	// +kubebuilder:validation:Enum=,valid,ready,pending,processing,invalid,expired,errored
	// +optional
	State State `json:"state,omitempty"`

	// Reason optionally provides more information about a why the order is in
	// the current state.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Challenges is a list of ChallengeSpecs for Challenges that must be created
	// in order to complete this Order.
	// +optional
	Challenges []ChallengeSpec `json:"challenges,omitempty"`

	// FailureTime stores the time that this order failed.
	// This is used to influence garbage collection and back-off.
	// +optional
	FailureTime *metav1.Time `json:"failureTime,omitempty"`
}

// State represents the state of an ACME resource, such as an Order.
// The possible options here map to the corresponding values in the
// ACME specification.
// Full details of these values can be found here: https://tools.ietf.org/html/draft-ietf-acme-acme-15#section-7.1.6
// Clients utilising this type must also gracefully handle unknown
// values, as the contents of this enumeration may be added to over time.
type State string

const (
	// Unknown is not a real state as part of the ACME spec.
	// It is used to represent an unrecognised value.
	Unknown State = ""

	// Valid signifies that an ACME resource is in a valid state.
	// If an order is 'valid', it has been finalized with the ACME server and
	// the certificate can be retrieved from the ACME server using the
	// certificate URL stored in the Order's status subresource.
	// This is a final state.
	Valid State = "valid"

	// Ready signifies that an ACME resource is in a ready state.
	// If an order is 'ready', all of its challenges have been completed
	// successfully and the order is ready to be finalized.
	// Once finalized, it will transition to the Valid state.
	// This is a transient state.
	Ready State = "ready"

	// Pending signifies that an ACME resource is still pending and is not yet ready.
	// If an Order is marked 'Pending', the validations for that Order are still in progress.
	// This is a transient state.
	Pending State = "pending"

	// Processing signifies that an ACME resource is being processed by the server.
	// If an Order is marked 'Processing', the validations for that Order are currently being processed.
	// This is a transient state.
	Processing State = "processing"

	// Invalid signifies that an ACME resource is invalid for some reason.
	// If an Order is marked 'invalid', one of its validations be have invalid for some reason.
	// This is a final state.
	Invalid State = "invalid"

	// Expired signifies that an ACME resource has expired.
	// If an Order is marked 'Expired', one of its validations may have expired or the Order itself.
	// This is a final state.
	Expired State = "expired"

	// Errored signifies that the ACME resource has errored for some reason.
	// This is a catch-all state, and is used for marking internal cert-manager
	// errors such as validation failures.
	// This is a final state.
	Errored State = "errored"
)

// SolverConfig is a container type holding the configuration for either a
// HTTP01 or DNS01 challenge.
// Only one of HTTP01 or DNS01 should be non-nil.
type SolverConfig struct {
	// HTTP01 contains HTTP01 challenge solving configuration
	// +optional
	HTTP01 *HTTP01SolverConfig `json:"http01,omitempty"`

	// DNS01 contains DNS01 challenge solving configuration
	// +optional
	DNS01 *DNS01SolverConfig `json:"dns01,omitempty"`
}

// HTTP01SolverConfig contains solver configuration for HTTP01 challenges.
type HTTP01SolverConfig struct {
	// Ingress is the name of an Ingress resource that will be edited to include
	// the ACME HTTP01 'well-known' challenge path in order to solve HTTP01
	// challenges.
	// If this field is specified, 'ingressClass' **must not** be specified.
	// +optional
	Ingress string `json:"ingress,omitempty"`

	// IngressClass is the ingress class that should be set on new ingress
	// resources that are created in order to solve HTTP01 challenges.
	// This field should be used when using an ingress controller such as nginx,
	// which 'flattens' ingress configuration instead of maintaining a 1:1
	// mapping between loadbalancer IP:ingress resources.
	// If this field is not set, and 'ingress' is not set, then ingresses
	// without an ingress class set will be created to solve HTTP01 challenges.
	// If this field is specified, 'ingress' **must not** be specified.
	// +optional
	IngressClass *string `json:"ingressClass,omitempty"`
}

// DNS01SolverConfig contains solver configuration for DNS01 challenges.
type DNS01SolverConfig struct {
	// Provider is the name of the DNS01 challenge provider to use, as configure
	// on the referenced Issuer or ClusterIssuer resource.
	Provider string `json:"provider"`
}

// DomainSolverConfig contains solver configuration for a set of domains.
type DomainSolverConfig struct {
	// Domains is the list of domains that this SolverConfig applies to.
	Domains []string `json:"domains"`

	// SolverConfig contains the actual solver configuration to use for the
	// provided set of domains.
	SolverConfig `json:",inline"`
}
