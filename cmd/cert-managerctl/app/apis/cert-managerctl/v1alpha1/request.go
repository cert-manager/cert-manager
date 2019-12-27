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

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

// Flags used for Requesting operations.
type Request struct {
	// Object Metadata to be used for the created CertificateRequest Kubernetes resource.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// ObjectReference to reference an Issuer to sign the certificate.
	IssuerRef cmmeta.ObjectReference `json:"issuerRef"`

	// Options related to requesting the certificate that are not directly
	// encoded into the x509 certificate request (duration, isCA, KeyUsages,
	// output file path).
	CertificateRequestSpec CertificateRequestSpec `json:"CertificateRequestSpec"`

	// Options for requesting certificates based on plain text options.
	// +optional
	Certificate *RequestCertificate `json:"certificate,omitempty"`

	// Options for requesting certificates based on CSR PEM inputs.
	// +optional
	Sign *RequestSign `json:"sign,omitempty"`

	Update *Update `json:"update,omitempty"`
}

// Options used for requesting certificates. A CSR PEM will be generated based
// on plain text input options.
type RequestCertificate struct {
	// Common Name field on the CSR.
	// +optional
	CommonName string `json:"commonName,omitempty"`

	// Organisations field on the CSR.
	// +optional
	Organizations []string `json:"organisations,omitempty"`

	// DNSNames field on the CSR.
	// +optional
	DNSNames []string `json:"dnsNames,omitempty"`

	// IPs field on the CSR.
	// +optional
	IPAddresses []string `json:"ipAddresses,omitempty"`

	// URIs field on the CSR.
	// +optional
	URISANs []string `json:"uriSANs,omitempty"`

	// File path to store the generated private key. If a private key is already
	// present at this location then this will be used when generating the CSR.
	Key string `json:"key,omitempty"`
}

// Options relating to the signing of a certificate based on a PEM encoded x509
// certificate request.
type RequestSign struct {
	// The file path where the PEM encoded x509 certificate request is located.
	// May be empty if we are reading from Stdin for example.
	// +optional
	CSRPEM string `json:"csrPEM,omitempty"`
}
