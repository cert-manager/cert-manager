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

// Flags used for Updating operations.
type Update struct {
	// Object Metadata to be used for the created CertificateRequest Kubernetes resource.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// The file path where the signed PEM encoded x509 certificate is located.
	// May be empty if we are reading from Stdin.
	// +optional
	CertificatePEM string `json"certificatePEM,omitempty"`

	// The file path where the PEM encoded x509 CA certificate is located.
	// May be empty.
	// +optional
	CAPEM string `json"certificatePEM,omitempty"`

	// The ready condition reason for updating the CertificateRequest.
	// Can be either one of:
	// - Pending
	// - Failed
	// - Issued
	ReadyConditionReason string `json"reason"`

	// An optional condition message for why the CertificateRequest has the
	// condition is does. This is especially useful for failed or pending
	// certificate requests.
	// +optional
	ReadyConditionMessage string `json"message"`
}
