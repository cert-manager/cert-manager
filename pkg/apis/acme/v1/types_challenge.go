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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:storageversion

// Challenge is a type to represent a Challenge request with an ACME server
// +k8s:openapi-gen=true
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Domain",type="string",JSONPath=".spec.dnsName"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.reason",description="",priority=1
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="CreationTimestamp is a timestamp representing the server time when this object was created. It is not guaranteed to be set in happens-before order across separate operations. Clients may not set this value. It is represented in RFC3339 form and is in UTC."
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=challenges
type Challenge struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec ChallengeSpec `json:"spec"`
	// +optional
	Status ChallengeStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ChallengeList is a list of Challenges
type ChallengeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Challenge `json:"items"`
}

type ChallengeSpec struct {
	// The URL of the ACME Challenge resource for this challenge.
	// This can be used to lookup details about the status of this challenge.
	URL string `json:"url"`

	// The URL to the ACME Authorization resource that this
	// challenge is a part of.
	AuthorizationURL string `json:"authorizationURL"`

	// dnsName is the identifier that this challenge is for, e.g. example.com.
	// If the requested DNSName is a 'wildcard', this field MUST be set to the
	// non-wildcard domain, e.g. for `*.example.com`, it must be `example.com`.
	DNSName string `json:"dnsName"`

	// wildcard will be true if this challenge is for a wildcard identifier,
	// for example '*.example.com'.
	// +optional
	Wildcard bool `json:"wildcard"`

	// The type of ACME challenge this resource represents.
	// One of "HTTP-01" or "DNS-01".
	Type ACMEChallengeType `json:"type"`

	// The ACME challenge token for this challenge.
	// This is the raw value returned from the ACME server.
	Token string `json:"token"`

	// The ACME challenge key for this challenge
	// For HTTP01 challenges, this is the value that must be responded with to
	// complete the HTTP01 challenge in the format:
	// `<private key JWK thumbprint>.<key from acme server for challenge>`.
	// For DNS01 challenges, this is the base64 encoded SHA256 sum of the
	// `<private key JWK thumbprint>.<key from acme server for challenge>`
	// text that must be set as the TXT record content.
	Key string `json:"key"`

	// Contains the domain solving configuration that should be used to
	// solve this challenge resource.
	Solver ACMEChallengeSolver `json:"solver"`

	// References a properly configured ACME-type Issuer which should
	// be used to create this Challenge.
	// If the Issuer does not exist, processing will be retried.
	// If the Issuer is not an 'ACME' Issuer, an error will be returned and the
	// Challenge will be marked as failed.
	IssuerRef cmmeta.ObjectReference `json:"issuerRef"`
}

// The type of ACME challenge. Only HTTP-01 and DNS-01 are supported.
// +kubebuilder:validation:Enum=HTTP-01;DNS-01
type ACMEChallengeType string

const (
	// ACMEChallengeTypeHTTP01 denotes a Challenge is of type http-01
	// More info: https://letsencrypt.org/docs/challenge-types/#http-01-challenge
	ACMEChallengeTypeHTTP01 ACMEChallengeType = "HTTP-01"

	// ACMEChallengeTypeDNS01 denotes a Challenge is of type dns-01
	// More info: https://letsencrypt.org/docs/challenge-types/#dns-01-challenge
	ACMEChallengeTypeDNS01 ACMEChallengeType = "DNS-01"
)

type ChallengeStatus struct {
	// Used to denote whether this challenge should be processed or not.
	// This field will only be set to true by the 'scheduling' component.
	// It will only be set to false by the 'challenges' controller, after the
	// challenge has reached a final state or timed out.
	// If this field is set to false, the challenge controller will not take
	// any more action.
	// +optional
	Processing bool `json:"processing"`

	// presented will be set to true if the challenge values for this challenge
	// are currently 'presented'.
	// This *does not* imply the self check is passing. Only that the values
	// have been 'submitted' for the appropriate challenge mechanism (i.e. the
	// DNS01 TXT record has been presented, or the HTTP01 configuration has been
	// configured).
	// +optional
	Presented bool `json:"presented"`

	// Contains human readable information on why the Challenge is in the
	// current state.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Contains the current 'state' of the challenge.
	// If not set, the state of the challenge is unknown.
	// +optional
	State State `json:"state,omitempty"`

	// List of status conditions to indicate the status of a Challenge.
	// Known condition types are (`SelfCheckSucceeded`, `DelayedAcceptTimeoutReached`)
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []ChallengeCondition `json:"conditions,omitempty"`
}

// ChallengeCondition contains condition information for a Challenge.
type ChallengeCondition struct {
	// Type of the condition, known values are (`SelfCheckSucceeded`, `DelayedAcceptTimeoutReached`).
	Type ChallengeConditionType `json:"type"`

	// Status of the condition, one of (`True`, `False`, `Unknown`).
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

	// If set, this represents the .metadata.generation that the condition was
	// set based upon.
	// For instance, if .metadata.generation is currently 12, but the
	// .status.condition[x].observedGeneration is 9, the condition is out of date
	// with respect to the current state of the Issuer.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// ChallengeConditionType represents an Issuer condition value.
type ChallengeConditionType string

const (
	// ChallengeConditionPresented means that the resources required for solving
	// the challenge have been deployed. For example DNS records or HTTP ingress
	// configuration.
	ChallengConditionPresented ChallengeConditionType = "Presented"

	// ChallengeConditionSelfCheckSucceeded means that a self check is passing,
	// and the ACME ‘authorization’ associated with this challenge will be
	// ‘accepted’.
	ChallengConditionSelfCheckSucceeded ChallengeConditionType = "SelfCheckSucceeded"

	// ChallengeConditionDelayedAcceptTimeoutReached means that the required
	// time has passed since the creation of the Challenge, and the ACME
	// ‘authorization’ associated with this challenge will be ‘accepted’.
	ChallengConditionDelayedAcceptTimeoutReached ChallengeConditionType = "DelayedAcceptTimeoutReached"
)
