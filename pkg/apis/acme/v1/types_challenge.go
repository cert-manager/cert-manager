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
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Domain",type="string",JSONPath=".spec.dnsName"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.reason",description="",priority=1
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="CreationTimestamp is a timestamp representing the server time when this object was created. It is not guaranteed to be set in happens-before order across separate operations. Clients may not set this value. It is represented in RFC3339 form and is in UTC."
// +kubebuilder:resource:scope=Namespaced,categories={cert-manager,cert-manager-acme}
// +kubebuilder:subresource:status

// Challenge is a type to represent a Challenge request with an ACME server
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

	// dnsName is the identifier that this challenge is for, e.g., example.com.
	// If the requested DNSName is a 'wildcard', this field MUST be set to the
	// non-wildcard domain, e.g., for `*.example.com`, it must be `example.com`.
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
	IssuerRef cmmeta.IssuerReference `json:"issuerRef"`
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

	// conditions contains the current observed conditions for the challenge.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []ChallengeCondition `json:"conditions,omitempty"`

	// Contains human readable information on why the Challenge is in the
	// current state.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Contains the current 'state' of the challenge.
	// If not set, the state of the challenge is unknown.
	// +optional
	State State `json:"state,omitempty"`

	// solver contains the observed status of an ACME challenge solver,
	// including DNS and HTTP-specific readiness data and general state tracking.
	//
	// This structure is used to track whether a challenge is ready to be submitted
	// to the ACME server for validation.
	// +optional
	Solver ChallengeSolverStatus `json:"solver,omitzero"`

	// nextReconcile is the timestamp that the next reconcile should be made.
	//
	// This exists as we have various polling going in within the challenge
	// controller with different backoff.
	// +optional
	NextReconcile *metav1.Time `json:"nextReconcile,omitempty"`
}

// ChallengeConditionType represents a Challenge condition value.
type ChallengeConditionType string

const (
	// ChallengeConditionTypePresented indicates that the challenge solver
	// has successfully presented the challenge token (e.g., by provisioning
	// a DNS record or serving an HTTP response).
	ChallengeConditionTypePresented = "Presented"
	// ChallengeConditionTypeSolved indicates that the presented solution
	// has propagated and is expected to be accessible to the ACME server.
	// This typically means DNS changes have propagated or HTTP endpoints are reachable.
	ChallengeConditionTypeSolved = "Solved"
	// ChallengeConditionTypeAccepted indicates that the ACME server has
	// validated and accepted the challenge response.
	ChallengeConditionTypeAccepted = "Accepted"
)

// ChallengeCondition contains condition information for a Challenge.
type ChallengeCondition struct {
	// type of the condition, known values are (`Presented`, `Solved`, `Accepted`).
	Type ChallengeConditionType `json:"type"`

	// status of the condition, one of (`True`, `False`, `Unknown`).
	Status cmmeta.ConditionStatus `json:"status"`

	// lastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// reason is a brief machine readable explanation for the condition's last
	// transition.
	Reason string `json:"reason"`

	// message is a human readable description of the details of the last
	// transition, complementing reason.
	Message string `json:"message,omitempty"`
}

// ChallengeSolverStatus contains the observed status of an ACME challenge solver,
// including DNS and HTTP-specific readiness data and general state tracking.
//
// This structure is used to track whether a challenge is ready to be submitted
// to the ACME server for validation.
type ChallengeSolverStatus struct {
	// dns contains status information specific to DNS-01 challenge solving.
	// +optional
	DNS *ChallengeSolverStatusDNS `json:"dns,omitempty"`

	// http contains status information specific to HTTP-01 challenge solving.
	// +optional
	HTTP *ChallengeSolverStatusHTTP `json:"http,omitempty"`
}

// ChallengeSolverStatusDNS provides details about DNS-01 challenge readiness checks.
type ChallengeSolverStatusDNS struct {
	// ttl is the configured time-to-live of the DNS record used for validation.
	// +optional
	TTL *metav1.Duration `json:"ttl,omitempty"`

	// lastSuccess is the time that the DNS check was successful against the
	// authoritative nameserver.
	//
	// The check will not pass until lastSuccess + ttl
	// has been reached to allow for DNSpropagation.
	// +optional
	LastSuccess *metav1.Time `json:"lastSuccess,omitempty"`

	// fqdn is the fully qualified domain name of the challenge
	// +optional
	FQDN string `json:"fqdn,omitempty"`
}

// ChallengeSolverStatusHTTP provides details about HTTP-01 challenge readiness checks.
type ChallengeSolverStatusHTTP struct {
	// requiredSuccesses is the number of successful HTTP requests required
	// to consider the challenge ready.
	// +optional
	RequiredSuccesses int64 `json:"requiredSuccesses"`

	// successes is the number of successful HTTP readiness checks observed so far.
	// +optional
	Successes int64 `json:"successes"`
}
