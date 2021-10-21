package config

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
	TLSConfig WebhookTLSConfig

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
}

// WebhookTLSConfig configures how TLS certificates are sourced for serving.
// Only one of 'filesystem' or 'dynamic' may be specified.
type WebhookTLSConfig struct {
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
	Filesystem WebhookFilesystemServingConfig

	// When Dynamic serving is enabled, the webhook will generate a CA used to sign webhook
	// certificates and persist it into a Kubernetes Secret resource (for other replicas of the
	// webhook to consume).
	// It will then generate a certificate in-memory for itself using this CA to serve with.
	// The CAs certificate can then be copied into the appropriate Validating, Mutating and Conversion
	// webhook configuration objects (typically by cainjector).
	Dynamic WebhookDynamicServingConfig
}

func (c *WebhookTLSConfig) FilesystemConfigProvided() bool {
	if c.Filesystem.KeyFile != "" || c.Filesystem.CertFile != "" {
		return true
	}
	return false
}

func (c *WebhookTLSConfig) DynamicConfigProvided() bool {
	if c.Dynamic.SecretNamespace != "" || c.Dynamic.SecretName != "" || len(c.Dynamic.DNSNames) > 0 {
		return true
	}
	return false
}

// WebhookDynamicServingConfig makes the webhook generate a CA and persist it into Secret resources.
// This CA will be used by all instances of the webhook for signing serving certificates.
type WebhookDynamicServingConfig struct {
	// Namespace of the Kubernetes Secret resource containing the TLS certificate
	// used as a CA to sign dynamic serving certificates.
	SecretNamespace string

	// Namespace of the Kubernetes Secret resource containing the TLS certificate
	// used as a CA to sign dynamic serving certificates.
	SecretName string

	// DNSNames that must be present on serving certificates signed by the CA.
	DNSNames []string
}

// WebhookFilesystemServingConfig enables using a certificate and private key found on the local filesystem.
// These files will be periodically polled in case they have changed, and dynamically reloaded.
type WebhookFilesystemServingConfig struct {
	// Path to a file containing TLS certificate & chain to serve with
	CertFile string

	// Path to a file containing a TLS private key to server with
	KeyFile string
}
