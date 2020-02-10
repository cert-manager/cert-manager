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

package v1alpha3

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

const (
	CertificateRequestReasonPending = "Pending"
	CertificateRequestReasonFailed  = "Failed"
	CertificateRequestReasonIssued  = "Issued"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CertificateRequest is a type to represent a Certificate Signing Request
// +k8s:openapi-gen=true
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
// +kubebuilder:printcolumn:name="Issuer",type="string",JSONPath=".spec.issuerRef.name",description="",priority=1
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message",priority=1
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="CreationTimestamp is a timestamp representing the server time when this object was created. It is not guaranteed to be set in happens-before order across separate operations. Clients may not set this value. It is represented in RFC3339 form and is in UTC."
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=certificaterequests,shortName=cr;crs
type CertificateRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateRequestSpec   `json:"spec,omitempty"`
	Status CertificateRequestStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CertificateRequestList is a list of Certificates
type CertificateRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []CertificateRequest `json:"items"`
}

// CertificateRequestSpec defines the desired state of CertificateRequest
type CertificateRequestSpec struct {
	// Requested certificate default Duration
	// +optional
	Duration *metav1.Duration `json:"duration,omitempty"`

	// IssuerRef is a reference to the issuer for this CertificateRequest.  If
	// the 'kind' field is not set, or set to 'Issuer', an Issuer resource with
	// the given name in the same namespace as the CertificateRequest will be
	// used.  If the 'kind' field is set to 'ClusterIssuer', a ClusterIssuer with
	// the provided name will be used. The 'name' field in this stanza is
	// required at all times. The group field refers to the API group of the
	// issuer which defaults to 'cert-manager.io' if empty.
	IssuerRef cmmeta.ObjectReference `json:"issuerRef"`

	// Byte slice containing the PEM encoded CertificateSigningRequest
	CSRPEM []byte `json:"csr"`

	// IsCA will mark the resulting certificate as valid for signing. This
	// implies that the 'cert sign' usage is set
	// +optional
	IsCA bool `json:"isCA,omitempty"`

	// Usages is the set of x509 actions that are enabled for a given key.
	// Defaults are ('digital signature', 'key encipherment') if empty
	// +optional
	Usages []KeyUsage `json:"usages,omitempty"`
}

// CertificateStatus defines the observed state of CertificateRequest and
// resulting signed certificate.
type CertificateRequestStatus struct {
	// +optional
	Conditions []CertificateRequestCondition `json:"conditions,omitempty"`

	// Byte slice containing a PEM encoded signed certificate resulting from the
	// given certificate signing request.
	// +optional
	Certificate []byte `json:"certificate,omitempty"`

	// Byte slice containing the PEM encoded certificate authority of the signed
	// certificate.
	// +optional
	CA []byte `json:"ca,omitempty"`

	// FailureTime stores the time that this CertificateRequest failed. This is
	// used to influence garbage collection and back-off.
	// +optional
	FailureTime *metav1.Time `json:"failureTime,omitempty"`
}

// CertificateRequestCondition contains condition information for a CertificateRequest.
type CertificateRequestCondition struct {
	// Type of the condition, currently ('Ready', 'InvalidRequest').
	Type CertificateRequestConditionType `json:"type"`

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

// CertificateRequestConditionType represents an Certificate condition value.
type CertificateRequestConditionType string

const (
	// CertificateRequestConditionReady indicates that a certificate is ready for use.
	// This is defined as:
	// - The target certificate exists in CertificateRequest.Status
	CertificateRequestConditionReady CertificateRequestConditionType = "Ready"
)
