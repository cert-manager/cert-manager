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
	"crypto"
	"crypto/x509"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
)

// The root flag struct wth global options.
type Flags struct {
	Kubeconfig string
	LogLevel   string

	Request Request
	Get     Get
	Update  Update
}

// A subset of the v1alpha2.CertificateRequestSpec resource to provide
// additional options that are not encoded into the x509 certificate request
// object.
type CertificateRequestSpec struct {
	// The duration as a Go passable duration string that set the requested
	// duration for the signed certificate to be valid for.
	// +optional
	Duration string `json:"duration,omitempty"`

	// Denote whether the signed certificate should be requested for marking as a CA.
	// +optional
	IsCA bool `json:"isCA,omitempty"`

	// The output file location to store the signed certificate. May be empty if
	// we are writing to Stdout for example.
	// +optional
	OutputFile string `json:"out,omitempty"`

	// A list of extended and non-extended key usages when requesting a signed
	// certificate.
	// +optional
	KeyUsages []cmapi.KeyUsage `json:"out,omitempty"`
}

// KeyBundle holds the signer and metadata of a PrivateKey
type KeyBundle struct {
	// PrivateKey signing interface
	// +optional
	PrivateKey crypto.Signer `json:"privateKey,omitempty"`

	// The signature algorithm type of the signature
	SignatureAlgorithm x509.SignatureAlgorithm `json:"signatureAlgorithm,omitempty"`

	// The signature algorithm type of the public key
	PublicKeyAlgorithm x509.PublicKeyAlgorithm `json:"publicKeyAlgorithm,omitempty"`
}
