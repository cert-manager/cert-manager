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
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// TODO: these types should be moved into their own API group once we have a loose
// coupling between ACME Issuers and their solver configurations (see: Solver proposal)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Challenge is a type to represent a Challenge request with an ACME server
// +k8s:openapi-gen=true
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Domain",type="string",JSONPath=".spec.dnsName"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.reason",description="",priority=1
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="CreationTimestamp is a timestamp representing the server time when this object was created. It is not guaranteed to be set in happens-before order across separate operations. Clients may not set this value. It is represented in RFC3339 form and is in UTC."
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

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ChallengePayload describes a request/response for presenting or cleaning up
// an ACME challenge resource
type ChallengePayload struct {
	metav1.TypeMeta `json:",inline"`

	// Request describes the attributes for the ACME solver request
	// +optional
	Request *ChallengeRequest `json:"request,omitempty" protobuf:"bytes,1,opt,name=request"`

	// Response describes the attributes for the ACME solver response
	// +optional
	Response *ChallengeResponse `json:"response,omitempty" protobuf:"bytes,2,opt,name=response"`
}

// ChallengeRequest is a payload that can be sent to external ACME webhook
// solvers in order to 'Present' or 'CleanUp' a challenge with an ACME server.
type ChallengeRequest struct {
	// UID is an identifier for the individual request/response. It allows us to distinguish instances of requests which are
	// otherwise identical (parallel requests, requests when earlier requests did not modify etc)
	// The UID is meant to track the round trip (request/response) between the KAS and the WebHook, not the user request.
	// It is suitable for correlating log entries between the webhook and apiserver, for either auditing or debugging.
	UID types.UID `json:"uid"`

	// Action is one of 'present' or 'cleanup'.
	// If the action is 'present', the record will be presented with the
	// solving service.
	// If the action is 'cleanup', the record will be cleaned up with the
	// solving service.
	Action ChallengeAction `json:"action"`

	// ResourceNamespace is the namespace containing resources that are
	// referenced in the providers config.
	// If this request is solving for an Issuer resource, this will be the
	// namespace of the Issuer.
	// If this request is solving for a ClusterIssuer resource, this will be
	// the configured 'cluster resource namespace'
	ResourceNamespace string `json:"resourceNamespace"`

	// ResolvedFQDN is the fully-qualified domain name that should be
	// updated/presented after resolving all CNAMEs.
	// This should be honoured when using the DNS01 solver type **only**
	// +optional
	ResolvedFQDN string `json:"resolvedFQDN,omitempty"`

	// Config contains unstructured JSON configuration data that the webhook
	// implementation can unmarshal in order to fetch secrets or configure
	// connection details etc.
	// Secret values should not be passed in this field, in favour of
	// references to Kubernetes Secret resources that the webhook can fetch.
	// +optional
	Config *apiext.JSON `json:"config,omitempty"`

	// Challenge is the specification of the challenge that is to be solved
	// The entire resource is included here, although the webhook itself
	// **must not** modify the challenge resource as part of presenting or
	// cleaning up the challenge.
	Challenge Challenge `json:"challenge"`
}

type ChallengeAction string

const (
	ChallengeActionPresent ChallengeAction = "Present"
	ChallengeActionCleanUp ChallengeAction = "CleanUp"
)

type ChallengeResponse struct {
	// UID is an identifier for the individual request/response.
	// This should be copied over from the corresponding ChallengeRequest.
	UID types.UID `json:"uid"`

	// Success will be set to true if the request action (i.e. presenting or
	// cleaning up) was successful.
	Success bool `json:"success"`

	// Result contains extra details into why a challenge request failed.
	// This field will be completely ignored if 'success' is true.
	// +optional
	Result *metav1.Status `json:"status,omitempty"`
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
	// +optional
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
	// +optional
	Processing bool `json:"processing"`

	// Presented will be set to true if the challenge values for this challenge
	// are currently 'presented'.
	// This *does not* imply the self check is passing. Only that the values
	// have been 'submitted' for the appropriate challenge mechanism (i.e. the
	// DNS01 TXT record has been presented, or the HTTP01 configuration has been
	// configured).
	// +optional
	Presented bool `json:"presented"`

	// Reason contains human readable information on why the Challenge is in the
	// current state.
	// +optional
	Reason string `json:"reason"`

	// State contains the current 'state' of the challenge.
	// If not set, the state of the challenge is unknown.
	// +kubebuilder:validation:Enum=,valid,ready,pending,processing,invalid,expired,errored
	// +optional
	State State `json:"state,omitempty"`
}
