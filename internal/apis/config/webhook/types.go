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

package webhook

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type WebhookConfiguration struct {
	metav1.TypeMeta

	// securePort is the port number to listen on for secure TLS connections from the kube-apiserver.
	// Defaults to 6443.
	SecurePort *int

	// healthzPort is the port number to listen on (using plaintext HTTP) for healthz connections.
	// Defaults to 6080.
	HealthzPort *int

	// tlsConfig is used to configure the secure listener's TLS settings.
	TLSConfig TLSConfig

	// kubeConfig is the kubeconfig file used to connect to the Kubernetes apiserver.
	// If not specified, the webhook will attempt to load the in-cluster-config.
	KubeConfig string

	// apiServerHost is used to override the API server connection address.
	// Deprecated: use `kubeConfig` instead.
	APIServerHost string

	// enablePprof configures whether pprof is enabled.
	EnablePprof bool

	// pprofAddress configures the address on which /debug/pprof endpoint will be served if enabled.
	// Defaults to 'localhost:6060'.
	PprofAddress string

	// featureGates is a map of feature names to bools that enable or disable experimental
	// features.
	// Default: nil
	// +optional
	FeatureGates map[string]bool
}

// TLSConfig configures how TLS certificates are sourced for serving.
// Only one of 'filesystem' or 'dynamic' may be specified.
type TLSConfig struct {
	// cipherSuites is the list of allowed cipher suites for the server.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	// If not specified, the default for the Go version will be used and may change over time.
	CipherSuites []string

	// minTLSVersion is the minimum TLS version supported.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	// If not specified, the default for the Go version will be used and may change over time.
	MinTLSVersion string

	// Filesystem enables using a certificate and private key found on the local filesystem.
	// These files will be periodically polled in case they have changed, and dynamically reloaded.
	Filesystem FilesystemServingConfig

	// When Dynamic serving is enabled, the webhook will generate a CA used to sign webhook
	// certificates and persist it into a Kubernetes Secret resource (for other replicas of the
	// webhook to consume).
	// It will then generate a certificate in-memory for itself using this CA to serve with.
	// The CAs certificate can then be copied into the appropriate Validating, Mutating and Conversion
	// webhook configuration objects (typically by cainjector).
	Dynamic DynamicServingConfig
}

func (c *TLSConfig) FilesystemConfigProvided() bool {
	if c.Filesystem.KeyFile != "" || c.Filesystem.CertFile != "" {
		return true
	}
	return false
}

func (c *TLSConfig) DynamicConfigProvided() bool {
	if c.Dynamic.SecretNamespace != "" || c.Dynamic.SecretName != "" || len(c.Dynamic.DNSNames) > 0 {
		return true
	}
	return false
}

// DynamicServingConfig makes the webhook generate a CA and persist it into Secret resources.
// This CA will be used by all instances of the webhook for signing serving certificates.
type DynamicServingConfig struct {
	// Namespace of the Kubernetes Secret resource containing the TLS certificate
	// used as a CA to sign dynamic serving certificates.
	SecretNamespace string

	// Namespace of the Kubernetes Secret resource containing the TLS certificate
	// used as a CA to sign dynamic serving certificates.
	SecretName string

	// DNSNames that must be present on serving certificates signed by the CA.
	DNSNames []string
}

// FilesystemServingConfig enables using a certificate and private key found on the local filesystem.
// These files will be periodically polled in case they have changed, and dynamically reloaded.
type FilesystemServingConfig struct {
	// Path to a file containing TLS certificate & chain to serve with
	CertFile string

	// Path to a file containing a TLS private key to server with
	KeyFile string
}
