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
	AuthzURL string `json:"authzURL"`
	Type     string `json:"type"`
	URL      string `json:"url"`
	DNSName  string `json:"dnsName"`
	Token    string `json:"token"`
	Key      string `json:"key"`
	Wildcard bool   `json:"wildcard"`

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
	Presented bool   `json:"presented"`
	Reason    string `json:"reason"`
	State     State  `json:"state"`
}
