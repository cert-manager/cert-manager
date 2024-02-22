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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logsapi "k8s.io/component-base/logs/api/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ControllerConfiguration struct {
	metav1.TypeMeta `json:",inline"`

	// kubeConfig is the kubeconfig file used to connect to the Kubernetes apiserver.
	// If not specified, the controller will attempt to load the in-cluster-config.
	KubeConfig string `json:"kubeConfig,omitempty"`

	// apiServerHost is used to override the API server connection address.
	// Deprecated: use `kubeConfig` instead.
	APIServerHost string `json:"apiServerHost,omitempty"`

	// Indicates the maximum queries-per-second requests to the Kubernetes apiserver
	// TODO: floats are not recommended. Maybe we should use resource.Quantity? https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/quantity/
	KubernetesAPIQPS *float32 `json:"kubernetesAPIQPS,omitempty"`

	// The maximum burst queries-per-second of requests sent to the Kubernetes apiserver
	KubernetesAPIBurst *int32 `json:"kubernetesAPIBurst,omitempty"`

	// If set, this limits the scope of cert-manager to a single namespace and
	// ClusterIssuers are disabled. If not specified, all namespaces will be
	// watched"
	Namespace string `json:"namespace,omitempty"`

	// Namespace to store resources owned by cluster scoped resources such as ClusterIssuer in.
	ClusterResourceNamespace string `json:"clusterResourceNamespace,omitempty"`

	// LeaderElectionConfig configures the behaviour of the leader election
	LeaderElectionConfig LeaderElectionConfig `json:"leaderElectionConfig"`

	// A list of controllers to enable.
	// ['*'] enables all controllers,
	// ['foo'] enables only the foo controller
	// ['*', '-foo'] disables the controller named foo.
	Controllers []string `json:"controllers,omitempty"`

	// Whether an issuer may make use of ambient credentials. 'Ambient
	// Credentials' are credentials drawn from the environment, metadata services,
	// or local files which are not explicitly configured in the Issuer API
	// object. When this flag is enabled, the following sources for
	// credentials are also used: AWS - All sources the Go SDK defaults to,
	// notably including any EC2 IAM roles available via instance metadata.
	IssuerAmbientCredentials *bool `json:"issuerAmbientCredentials,omitempty"`

	// Whether a cluster-issuer may make use of ambient credentials for issuers.
	// 'Ambient Credentials' are credentials drawn from the environment, metadata
	// services, or local files which are not explicitly configured in the
	// ClusterIssuer API object. When this flag is enabled, the following sources
	// for credentials are also used: AWS - All sources the Go SDK defaults to,
	// notably including any EC2 IAM roles available via instance metadata.
	ClusterIssuerAmbientCredentials *bool `json:"clusterIssuerAmbientCredentials,omitempty"`

	// Whether to set the certificate resource as an owner of secret where the
	// tls certificate is stored. When this flag is enabled, the secret will be
	// automatically removed when the certificate resource is deleted.
	EnableCertificateOwnerRef *bool `json:"enableCertificateOwnerRef,omitempty"`

	// Specify which annotations should/shouldn't be copied from Certificate to
	// CertificateRequest and Order, as well as from CertificateSigningRequest to
	// Order, by passing a list of annotation key prefixes. A prefix starting with
	// a dash(-) specifies an annotation that shouldn't be copied. Example:
	// '*,-kubectl.kuberenetes.io/'- all annotations will be copied apart from the
	// ones where the key is prefixed with 'kubectl.kubernetes.io/'.
	CopiedAnnotationPrefixes []string `json:"copiedAnnotationPrefixes,omitempty"`

	// The number of concurrent workers for each controller.
	NumberOfConcurrentWorkers *int32 `json:"numberOfConcurrentWorkers,omitempty"`

	// The maximum number of challenges that can be scheduled as 'processing' at once.
	MaxConcurrentChallenges *int32 `json:"maxConcurrentChallenges,omitempty"`

	// The host and port that the metrics endpoint should listen on.
	MetricsListenAddress string `json:"metricsListenAddress,omitempty"`

	// TLS config for the metrics endpoint
	MetricsTLSConfig TLSConfig `json:"metricsTLSConfig"`

	// The host and port address, separated by a ':', that the healthz server
	// should listen on.
	HealthzListenAddress string `json:"healthzListenAddress,omitempty"`

	// Enable profiling for controller.
	EnablePprof *bool `json:"enablePprof"`

	// The host and port that Go profiler should listen on, i.e localhost:6060.
	// Ensure that profiler is not exposed on a public address. Profiler will be
	// served at /debug/pprof.
	PprofAddress string `json:"pprofAddress,omitempty"`

	// logging configures the logging behaviour of the controller.
	// https://pkg.go.dev/k8s.io/component-base@v0.27.3/logs/api/v1#LoggingConfiguration
	Logging logsapi.LoggingConfiguration `json:"logging"`

	// featureGates is a map of feature names to bools that enable or disable experimental
	// features.
	// +optional
	FeatureGates map[string]bool `json:"featureGates,omitempty"`

	// ingressShimConfig configures the behaviour of the ingress-shim controller
	IngressShimConfig IngressShimConfig `json:"ingressShimConfig,omitempty"`

	// acmeHTTP01Config configures the behaviour of the ACME HTTP01 challenge solver
	ACMEHTTP01Config ACMEHTTP01Config `json:"acmeHTTP01Config,omitempty"`

	// acmeDNS01Config configures the behaviour of the ACME DNS01 challenge solver
	ACMEDNS01Config ACMEDNS01Config `json:"acmeDNS01Config,omitempty"`
}

type KubeConfig struct {
	// Path to a kubeconfig. Only required if out-of-cluster.
	Path string `json:"path,omitempty"`

	// If true, use the current context from the kubeconfig file.
	// If false, use the context specified by ControllerConfiguration.Context.
	// Default: true
	// +optional
	CurrentContext *bool `json:"currentContext,omitempty"`

	// The kubeconfig context to use.
	// Default: current-context from kubeconfig file
	// +optional
	Context string `json:"context,omitempty"`
}

type LeaderElectionConfig struct {
	// If true, cert-manager will perform leader election between instances to
	// ensure no more than one instance of cert-manager operates at a time
	Enabled *bool `json:"enabled,omitempty"`

	// Namespace used to perform leader election. Only used if leader election is enabled
	Namespace string `json:"namespace,omitempty"`

	// The duration that non-leader candidates will wait after observing a leadership
	// renewal until attempting to acquire leadership of a led but unrenewed leader
	// slot. This is effectively the maximum duration that a leader can be stopped
	// before it is replaced by another candidate. This is only applicable if leader
	// election is enabled.
	LeaseDuration time.Duration `json:"leaseDuration,omitempty"`

	// The interval between attempts by the acting master to renew a leadership slot
	// before it stops leading. This must be less than or equal to the lease duration.
	// This is only applicable if leader election is enabled.
	RenewDeadline time.Duration `json:"renewDeadline,omitempty"`

	// The duration the clients should wait between attempting acquisition and renewal
	// of a leadership. This is only applicable if leader election is enabled.
	RetryPeriod time.Duration `json:"retryPeriod,omitempty"`

	// Leader election healthz checks within this timeout period after the lease
	// expires will still return healthy.
	HealthzTimeout time.Duration `json:"healthzTimeout,omitempty"`
}

type IngressShimConfig struct {
	// Default issuer/certificates details consumed by ingress-shim
	// Name of the Issuer to use when the tls is requested but issuer name is
	// not specified on the ingress resource.
	DefaultIssuerName string `json:"defaultIssuerName,omitempty"`

	// Kind of the Issuer to use when the TLS is requested but issuer kind is not
	// specified on the ingress resource.
	DefaultIssuerKind string `json:"defaultIssuerKind,omitempty"`

	// Group of the Issuer to use when the TLS is requested but issuer group is
	// not specified on the ingress resource.
	DefaultIssuerGroup string `json:"defaultIssuerGroup,omitempty"`

	// The annotation consumed by the ingress-shim controller to indicate a ingress
	// is requesting a certificate
	DefaultAutoCertificateAnnotations []string `json:"defaultAutoCertificateAnnotations,omitempty"`
}

type ACMEHTTP01Config struct {
	// The Docker image to use to solve ACME HTTP01 challenges. You most likely
	// will not need to change this parameter unless you are testing a new
	// feature or developing cert-manager.
	SolverImage string `json:"solverImage,omitempty"`

	// Defines the resource request CPU size when spawning new ACME HTTP01
	// challenge solver pods.
	SolverResourceRequestCPU string `json:"solverResourceRequestCPU,omitempty"`

	// Defines the resource request Memory size when spawning new ACME HTTP01
	// challenge solver pods.
	SolverResourceRequestMemory string `json:"solverResourceRequestMemory,omitempty"`

	// Defines the resource limits CPU size when spawning new ACME HTTP01
	// challenge solver pods.
	SolverResourceLimitsCPU string `json:"solverResourceLimitsCPU,omitempty"`

	// Defines the resource limits Memory size when spawning new ACME HTTP01
	// challenge solver pods.
	SolverResourceLimitsMemory string `json:"solverResourceLimitsMemory,omitempty"`

	// Defines the ability to run the http01 solver as root for troubleshooting
	// issues
	SolverRunAsNonRoot *bool `json:"solverRunAsNonRoot,omitempty"`

	// A list of comma separated dns server endpoints used for
	// ACME HTTP01 check requests. This should be a list containing host and
	// port, for example ["8.8.8.8:53","8.8.4.4:53"]
	// Allows specifying a list of custom nameservers to perform HTTP01 checks on.
	SolverNameservers []string `json:"solverNameservers,omitempty"`
}

type ACMEDNS01Config struct {
	// Each nameserver can be either the IP address and port of a standard
	// recursive DNS server, or the endpoint to an RFC 8484 DNS over HTTPS
	// endpoint. For example, the following values are valid:
	//  - "8.8.8.8:53" (Standard DNS)
	//  - "https://1.1.1.1/dns-query" (DNS over HTTPS)
	RecursiveNameservers []string `json:"recursiveNameservers,omitempty"`

	// When true, cert-manager will only ever query the configured DNS resolvers
	// to perform the ACME DNS01 self check. This is useful in DNS constrained
	// environments, where access to authoritative nameservers is restricted.
	// Enabling this option could cause the DNS01 self check to take longer
	// due to caching performed by the recursive nameservers.
	RecursiveNameserversOnly *bool `json:"recursiveNameserversOnly,omitempty"`

	// The duration the controller should wait between a propagation check. Despite
	// the name, this flag is used to configure the wait period for both DNS01 and
	// HTTP01 challenge propagation checks. For DNS01 challenges the propagation
	// check verifies that a TXT record with the challenge token has been created.
	// For HTTP01 challenges the propagation check verifies that the challenge
	// token is served at the challenge URL. This should be a valid duration
	// string, for example 180s or 1h
	CheckRetryPeriod time.Duration `json:"checkRetryPeriod,omitempty"`
}

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
	LeafDuration time.Duration
}

// FilesystemServingConfig enables using a certificate and private key found on the local filesystem.
// These files will be periodically polled in case they have changed, and dynamically reloaded.
type FilesystemServingConfig struct {
	// Path to a file containing TLS certificate & chain to serve with
	CertFile string `json:"certFile,omitempty"`

	// Path to a file containing a TLS private key to serve with
	KeyFile string `json:"keyFile,omitempty"`
}
