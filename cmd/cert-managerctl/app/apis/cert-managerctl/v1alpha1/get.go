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

// Options related to retrieving certificates from Kubernetes.
type Get struct {
	// Object Metadata of the target CertificateRequest to retrieve the signed certificate from.
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Options related to retrieving a PEM encoded x509 signed certificate.
	// +optional
	Certificate *GetCertificate `json:"csrPEM,omitempty"`
}

// Options related to retrieving a PEM encoded x509 signed certificate.
type GetCertificate struct {
	// Output file location to store the signed certificate. May be empty if we
	// are outputting to Stdout for example.
	// +optional
	OutputFile string `json:"out,omitempty"`

	// Whether we should wait for a timeout for the target CertificateRequest to
	// become ready.
	// +optional
	Wait bool `json:"wait,omitempty"`
}
