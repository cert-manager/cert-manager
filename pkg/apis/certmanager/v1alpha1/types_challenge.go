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
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// +kubebuilder:resource:path=challenges
type Challenge struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   ChallengeSpec   `json:"spec"`
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
	// AuthzURL is the URL to the ACME Authorization resource that this
	// challenge is a part of.
	AuthzURL string `json:"authzURL"`

	// Type is the type of ACME challenge this resource represents, e.g. "dns01"
	// or "http01"
	Type string `json:"type"`

	// URL is the URL of the ACME Challenge resource for this challenge.
	// This can be used to lookup details about the status of this challenge.
	URL string `json:"url"`

	// DNSName is the identifier that this challenge is for, e.g. example.com.
	DNSName string `json:"dnsName"`

	// Token is the ACME challenge token for this challenge.
	Token string `json:"token"`

	// Key is the ACME challenge key for this challenge
	Key string `json:"key"`

	// Wildcard will be true if this challenge is for a wildcard identifier,
	// for example '*.example.com'
	Wildcard bool `json:"wildcard"`

	// Config specifies the solver configuration for this challenge.
	Config SolverConfig `json:"config"`

	// IssuerRef references a properly configured ACME-type Issuer which should
	// be used to create this Challenge.
	// If the Issuer does not exist, processing will be retried.
	// If the Issuer is not an 'ACME' Issuer, an error will be returned and the
	// Challenge will be marked as failed.
	IssuerRef ObjectReference `json:"issuerRef"`
}

type ChallengeStatus struct {
	// Processing is used to denote whether this challenge should be processed
	// or not.
	// This field will only be set to true by the 'scheduling' component.
	// It will only be set to false by the 'challenges' controller, after the
	// challenge has reached a final state or timed out.
	// If this field is set to false, the challenge controller will not take
	// any more action.
	Processing bool `json:"processing"`

	// Presented will be set to true if the challenge values for this challenge
	// are currently 'presented'.
	// This *does not* imply the self check is passing. Only that the values
	// have been 'submitted' for the appropriate challenge mechanism (i.e. the
	// DNS01 TXT record has been presented, or the HTTP01 configuration has been
	// configured).
	Presented bool `json:"presented"`

	// Reason contains human readable information on why the Challenge is in the
	// current state.
	Reason string `json:"reason"`

	// State contains the current 'state' of the challenge.
	// If not set, the state of the challenge is unknown.
	State State `json:"state"`
}
