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

package controller

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logsapi "k8s.io/component-base/logs/api/v1"

	shared "github.com/cert-manager/cert-manager/internal/apis/config/shared"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ControllerConfiguration struct {
	metav1.TypeMeta

	// Optional apiserver host address to connect to. If not specified,
	// autoconfiguration will be attempted
	APIServerHost string

	// Paths to a kubeconfig. Only required if out-of-cluster.
	KubeConfig string

	// Indicates the maximum queries-per-second requests to the Kubernetes apiserver
	KubernetesAPIQPS float32

	// The maximum burst queries-per-second of requests sent to the Kubernetes apiserver
	KubernetesAPIBurst int

	// If set, this limits the scope of cert-manager to a single namespace and
	// ClusterIssuers are disabled. If not specified, all namespaces will be
	// watched
	Namespace string

	// Namespace to store resources owned by cluster scoped resources such as ClusterIssuer in.
	ClusterResourceNamespace string

	// LeaderElectionConfig configures the behaviour of the leader election
	LeaderElectionConfig LeaderElectionConfig

	// A list of controllers to enable.
	// ['*'] enables all controllers,
	// ['foo'] enables only the foo controller
	// ['*', '-foo'] disables the controller named foo.
	Controllers []string

	// Whether an issuer may make use of ambient credentials. 'Ambient
	// Credentials' are credentials drawn from the environment, metadata services,
	// or local files which are not explicitly configured in the Issuer API
	// object. When this flag is enabled, the following sources for
	// credentials are also used: AWS - All sources the Go SDK defaults to,
	// notably including any EC2 IAM roles available via instance metadata.
	IssuerAmbientCredentials bool

	// Whether a cluster-issuer may make use of ambient credentials for issuers.
	// 'Ambient Credentials' are credentials drawn from the environment, metadata
	// services, or local files which are not explicitly configured in the
	// ClusterIssuer API object. When this flag is enabled, the following sources
	// for credentials are also used: AWS - All sources the Go SDK defaults to,
	// notably including any EC2 IAM roles available via instance metadata.
	ClusterIssuerAmbientCredentials bool

	// Whether to set the certificate resource as an owner of secret where the
	// tls certificate is stored. When this flag is enabled, the secret will be
	// automatically removed when the certificate resource is deleted.
	EnableCertificateOwnerRef bool

	// Whether gateway API integration is enabled within cert-manager. The
	// ExperimentalGatewayAPISupport feature gate must also be enabled (default
	// as of 1.15).
	EnableGatewayAPI bool

	// Specify which annotations should/shouldn't be copied from Certificate to
	// CertificateRequest and Order, as well as from CertificateSigningRequest to
	// Order, by passing a list of annotation key prefixes. A prefix starting with
	// a dash(-) specifies an annotation that shouldn't be copied. Example:
	// '*,-kubectl.kubernetes.io/'- all annotations will be copied apart from the
	// ones where the key is prefixed with 'kubectl.kubernetes.io/'.
	CopiedAnnotationPrefixes []string

	// The number of concurrent workers for each controller.
	NumberOfConcurrentWorkers int

	// The maximum number of challenges that can be scheduled as 'processing' at once.
	MaxConcurrentChallenges int

	// The host and port that the metrics endpoint should listen on.
	MetricsListenAddress string

	// Metrics endpoint TLS config
	MetricsTLSConfig shared.TLSConfig

	// The host and port address, separated by a ':', that the healthz server
	// should listen on.
	HealthzListenAddress string

	// Enable profiling for controller.
	EnablePprof bool

	// The host and port that Go profiler should listen on, i.e localhost:6060.
	// Ensure that profiler is not exposed on a public address. Profiler will be
	// served at /debug/pprof.
	PprofAddress string

	// https://pkg.go.dev/k8s.io/component-base@v0.27.3/logs/api/v1#LoggingConfiguration
	Logging logsapi.LoggingConfiguration

	// featureGates is a map of feature names to bools that enable or disable experimental
	// features.
	FeatureGates map[string]bool

	// IngressShimConfig configures the behaviour of the ingress-shim controller
	IngressShimConfig IngressShimConfig

	// ACMEHTTP01Config configures the behaviour of the ACME HTTP01 challenge solver
	ACMEHTTP01Config ACMEHTTP01Config

	// ACMEDNS01Config configures the behaviour of the ACME DNS01 challenge solver
	ACMEDNS01Config ACMEDNS01Config
}

type LeaderElectionConfig struct {
	shared.LeaderElectionConfig

	// Leader election healthz checks within this timeout period after the lease
	// expires will still return healthy.
	HealthzTimeout time.Duration
}

type IngressShimConfig struct {
	// Default issuer/certificates details consumed by ingress-shim
	// Name of the Issuer to use when the tls is requested but issuer name is
	// not specified on the ingress resource.
	DefaultIssuerName string

	// Kind of the Issuer to use when the TLS is requested but issuer kind is not
	// specified on the ingress resource.
	DefaultIssuerKind string

	// Group of the Issuer to use when the TLS is requested but issuer group is
	// not specified on the ingress resource.
	DefaultIssuerGroup string

	// The annotation consumed by the ingress-shim controller to indicate an ingress
	// is requesting a certificate
	DefaultAutoCertificateAnnotations []string

	// ExtraCertificateAnnotations is a list of annotations which should be copied from
	// and ingress-like object to a Certificate.
	ExtraCertificateAnnotations []string
}

type ACMEHTTP01Config struct {
	// The Docker image to use to solve ACME HTTP01 challenges. You most likely
	// will not need to change this parameter unless you are testing a new
	// feature or developing cert-manager.
	SolverImage string

	// Defines the resource request CPU size when spawning new ACME HTTP01
	// challenge solver pods.
	SolverResourceRequestCPU string

	// Defines the resource request Memory size when spawning new ACME HTTP01
	// challenge solver pods.
	SolverResourceRequestMemory string

	// Defines the resource limits CPU size when spawning new ACME HTTP01
	// challenge solver pods.
	SolverResourceLimitsCPU string

	// Defines the resource limits Memory size when spawning new ACME HTTP01
	// challenge solver pods.
	SolverResourceLimitsMemory string

	// Defines the ability to run the http01 solver as root for troubleshooting
	// issues
	SolverRunAsNonRoot bool

	// A list of comma separated dns server endpoints used for
	// ACME HTTP01 check requests. This should be a list containing host and
	// port, for example ["8.8.8.8:53","8.8.4.4:53"]
	// Allows specifying a list of custom nameservers to perform HTTP01 checks on.
	SolverNameservers []string
}

type ACMEDNS01Config struct {
	// Each nameserver can be either the IP address and port of a standard
	// recursive DNS server, or the endpoint to an RFC 8484 DNS over HTTPS
	// endpoint. For example, the following values are valid:
	//  - "8.8.8.8:53" (Standard DNS)
	//  - "https://1.1.1.1/dns-query" (DNS over HTTPS)
	RecursiveNameservers []string

	// When true, cert-manager will only ever query the configured DNS resolvers
	// to perform the ACME DNS01 self check. This is useful in DNS constrained
	// environments, where access to authoritative nameservers is restricted.
	// Enabling this option could cause the DNS01 self check to take longer
	// due to caching performed by the recursive nameservers.
	RecursiveNameserversOnly bool

	// The duration the controller should wait between a propagation check. Despite
	// the name, this flag is used to configure the wait period for both DNS01 and
	// HTTP01 challenge propagation checks. For DNS01 challenges the propagation
	// check verifies that a TXT record with the challenge token has been created.
	// For HTTP01 challenges the propagation check verifies that the challenge
	// token is served at the challenge URL. This should be a valid duration
	// string, for example 180s or 1h
	CheckRetryPeriod time.Duration
}
