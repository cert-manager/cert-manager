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

package acme

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmmeta "github.com/cert-manager/cert-manager/internal/apis/meta"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Challenge is a type to represent a Challenge request with an ACME server
type Challenge struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   ChallengeSpec
	Status ChallengeStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ChallengeList is a list of Challenges
type ChallengeList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []Challenge
}

type ChallengeSpec struct {
	// The URL of the ACME Challenge resource for this challenge.
	// This can be used to lookup details about the status of this challenge.
	URL string

	// The URL to the ACME Authorization resource that this
	// challenge is a part of.
	AuthorizationURL string

	// dnsName is the identifier that this challenge is for, e.g., example.com.
	// If the requested DNSName is a 'wildcard', this field MUST be set to the
	// non-wildcard domain, e.g., for `*.example.com`, it must be `example.com`.
	DNSName string

	// wildcard will be true if this challenge is for a wildcard identifier,
	// for example '*.example.com'.
	Wildcard bool

	// The type of ACME challenge this resource represents.
	// One of "HTTP-01" or "DNS-01".
	Type ACMEChallengeType

	// The ACME challenge token for this challenge.
	// This is the raw value returned from the ACME server.
	Token string

	// The ACME challenge key for this challenge
	// For HTTP01 challenges, this is the value that must be responded with to
	// complete the HTTP01 challenge in the format:
	// `<private key JWK thumbprint>.<key from acme server for challenge>`.
	// For DNS01 challenges, this is the base64 encoded SHA256 sum of the
	// `<private key JWK thumbprint>.<key from acme server for challenge>`
	// text that must be set as the TXT record content.
	Key string

	// Contains the domain solving configuration that should be used to
	// solve this challenge resource.
	Solver ACMEChallengeSolver

	// References a properly configured ACME-type Issuer which should
	// be used to create this Challenge.
	// If the Issuer does not exist, processing will be retried.
	// If the Issuer is not an 'ACME' Issuer, an error will be returned and the
	// Challenge will be marked as failed.
	IssuerRef cmmeta.IssuerReference
}

// The type of ACME challenge. Only HTTP-01 and DNS-01 are supported.
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
	// Processing is used to denote whether this challenge should be processed
	// or not.
	// This field will only be set to true by the 'scheduling' component.
	// It will only be set to false by the 'challenges' controller, after the
	// challenge has reached a final state or timed out.
	// If this field is set to false, the challenge controller will not take
	// any more action.
	Processing bool

	// Presented will be set to true if the challenge values for this challenge
	// are currently 'presented'.
	// This *does not* imply the self check is passing. Only that the values
	// have been 'submitted' for the appropriate challenge mechanism (i.e. the
	// DNS01 TXT record has been presented, or the HTTP01 configuration has been
	// configured).
	Presented bool

	// Reason contains human readable information on why the Challenge is in the
	// current state.
	Reason string

	// State contains the current 'state' of the challenge.
	// If not set, the state of the challenge is unknown.
	State State
}
