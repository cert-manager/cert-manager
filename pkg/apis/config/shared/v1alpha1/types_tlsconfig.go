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

// TLSConfig configures how TLS certificates are sourced for serving.
// Only one of 'filesystem' or 'dynamic' may be specified.
type TLSConfig struct {
	// cipherSuites is the list of allowed cipher suites for the server.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	// If not specified, the default for the Go version will be used and may change over time.
	CipherSuites []string `json:"cipherSuites,omitempty"`

	// minTLSVersion is the minimum TLS version supported.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	// If not specified, the default for the Go version will be used and may change over time.
	MinTLSVersion string `json:"minTLSVersion,omitempty"`

	// Filesystem enables using a certificate and private key found on the local filesystem.
	// These files will be periodically polled in case they have changed, and dynamically reloaded.
	Filesystem FilesystemServingConfig `json:"filesystem"`

	// When Dynamic serving is enabled, the controller will generate a CA used to sign
	// certificates and persist it into a Kubernetes Secret resource (for other replicas of the
	// controller to consume).
	// It will then generate a certificate in-memory for itself using this CA to serve with.
	Dynamic DynamicServingConfig `json:"dynamic"`
}

// DynamicServingConfig makes the controller generate a CA and persist it into Secret resources.
// This CA will be used by all instances of the controller for signing serving certificates.
type DynamicServingConfig struct {
	// Namespace of the Kubernetes Secret resource containing the TLS certificate
	// used as a CA to sign dynamic serving certificates.
	SecretNamespace string `json:"secretNamespace,omitempty"`

	// Secret resource name containing the TLS certificate
	// used as a CA to sign dynamic serving certificates.
	SecretName string `json:"secretName,omitempty"`

	// DNSNames that must be present on serving certificates signed by the CA.
	DNSNames []string `json:"dnsNames,omitempty"`

	// LeafDuration is a customizable duration on serving certificates signed by the CA.
	LeafDuration *Duration `json:"leafDuration,omitempty"`
}

// FilesystemServingConfig enables using a certificate and private key found on the local filesystem.
// These files will be periodically polled in case they have changed, and dynamically reloaded.
type FilesystemServingConfig struct {
	// Path to a file containing TLS certificate & chain to serve with
	CertFile string `json:"certFile,omitempty"`

	// Path to a file containing a TLS private key to serve with
	KeyFile string `json:"keyFile,omitempty"`
}
