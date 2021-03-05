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

package policy

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type CertificateRequestPolicy struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec CertificateRequestPolicySpec

	Status CertificateRequestPolicyStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type CertificateRequestPolicyList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []CertificateRequestPolicy
}

type CertificateRequestPolicySpec struct {
	AllowedSubject *PolicyX509Subject

	AllowedCommonName *string

	// Values are inclusive (i.e. a min value with 50s will accept a duration
	// with 50s). MinDuration and MaxDuration may be the same.
	MinDuration *metav1.Duration
	MaxDuration *metav1.Duration

	AllowedDNSNames *[]string

	AllowedIPAddresses *[]string

	AllowedURIs *[]string

	AllowedEmailAddresses *[]string

	AllowedIssuers *[]cmmeta.ObjectReference

	AllowedIsCA *bool

	AllowedUsages *[]cmapi.KeyUsage

	AllowedPrivateKey *PolicyPrivateKey

	ExternalPolicyServers []string
}

type PolicyX509Subject struct {
	AllowedOrganizations       *[]string
	AllowedCountries           *[]string
	AllowedOrganizationalUnits *[]string
	AllowedLocalities          *[]string
	AllowedProvinces           *[]string
	AllowedStreetAddresses     *[]string
	AllowedPostalCodes         *[]string
	AllowedSerialNumber        *string
}

type PolicyPrivateKey struct {
	AllowedAlgorithm *cmapi.PrivateKeyAlgorithm

	// Values are inclusive (i.e. a min value with 2048 will accept a size of
	// 2048). MinSize and MaxSize may be the same.
	MinSize *int
	MaxSize *int
}

type CertificateRequestPolicyStatus struct {
	Conditions []CertificateRequestPolicyCondition
}

type CertificateRequestPolicyCondition struct {
	Type   CertificateRequestPolicyConditionType
	Status cmmeta.ConditionStatus

	LastTransitionTime *metav1.Time

	Reason string

	Message string

	ObservedGeneration int64
}

type CertificateRequestPolicyConditionType string

const (
	CertificateRequestPolicyConditionReady CertificateRequestPolicyConditionType = "Ready"
)
