/*
Copyright 2021 The cert-manager Authors.

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

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

// TODO: openapi validation

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:storageversion

// +k8s:openapi-gen=true
type CertificateRequestPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec CertificateRequestPolicySpec `json:"spec"`

	// +optional
	Status CertificateRequestPolicyStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type CertificateRequestPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []CertificateRequestPolicy `json:"items"`
}

type CertificateRequestPolicySpec struct {
	// +optional
	AllowedSubject *PolicyX509Subject `json:"allowedSubject,omitempty"`

	// +optional
	AllowedCommonName *string `json:"subject,omitempty"`

	// Values are inclusive (i.e. a min value with 50s will accept a duration
	// with 50s). MinDuration and MaxDuration may be the same.
	// +optional
	MinDuration *metav1.Duration `json:"minDuration,omitempty"`
	// +optional
	MaxDuration *metav1.Duration `json:"maxDuration,omitempty"`

	// +optional
	AllowedDNSNames *[]string `json:"allowedDNSNames,omitempty"`

	// +optional
	AllowedIPAddresses *[]string `json:"allowedIPAddresses,omitempty"`

	// +optional
	AllowedURIs *[]string `json:"allowedURIs,omitempty"`

	// +optional
	AllowedEmailAddresses *[]string `json:"allowedEmailAddresses,omitempty"`

	// +optional
	AllowedIssuers *[]cmmeta.ObjectReference `json:"allowedIssuer,omitempty"`

	// +optional
	AllowedIsCA *bool `json:"allowedIsCA,omitempty"`

	// +optional
	AllowedUsages *[]cmapi.KeyUsage `json:"allowedUsages,omitempty"`

	// +optional
	AllowedPrivateKey *PolicyPrivateKey `json:"allowedPrivateKey,omitempty"`

	// +optional
	ExternalPolicyServers []string `json:"externalPolicyServers,omitempty"`
}

type PolicyX509Subject struct {
	// +optional
	AllowedOrganizations *[]string `json:"allowedOrganizations,omitempty"`
	// +optional
	AllowedCountries *[]string `json:"allowedCountries,omitempty"`
	// +optional
	AllowedOrganizationalUnits *[]string `json:"allowedOrganizationalUnits,omitempty"`
	// +optional
	AllowedLocalities *[]string `json:"allowedLocalities,omitempty"`
	// +optional
	AllowedProvinces *[]string `json:"allowedProvinces,omitempty"`
	// +optional
	AllowedStreetAddresses *[]string `json:"allowedStreetAddresses,omitempty"`
	// +optional
	AllowedPostalCodes *[]string `json:"allowedPostalCodes,omitempty"`
	// +optional
	AllowedSerialNumber *string `json:"allowedSerialNumber,omitempty"`
}

type PolicyPrivateKey struct {
	// +optional
	AllowedAlgorithm *cmapi.PrivateKeyAlgorithm `json:"allowedAlgorithm,omitempty"`

	// Values are inclusive (i.e. a min value with 2048 will accept a size of
	// 2048). MinSize and MaxSize may be the same.
	// +optional
	MinSize *int `json:"allowedMinSize,omitempty"`
	// +optional
	MaxSize *int `json:"allowedMaxSize,omitempty"`
}

type CertificateRequestPolicyStatus struct {
	// +optional
	Conditions []CertificateRequestPolicyCondition `json:"conditions,omitempty"`
}

type CertificateRequestPolicyCondition struct {
	Type   CertificateRequestPolicyConditionType `json:"type"`
	Status cmmeta.ConditionStatus                `json:"status"`

	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// +optional
	Reason string `json:"reason,omitempty"`

	// +optional
	Message string `json:"message,omitempty"`

	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

type CertificateRequestPolicyConditionType string

const (
	CertificateRequestPolicyConditionReady CertificateRequestPolicyConditionType = "Ready"
)
