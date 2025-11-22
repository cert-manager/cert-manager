/*
Copyright 2020 The cert-manager Authors.

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

package options

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	cliflag "k8s.io/component-base/cli/flag"

	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
	configscheme "github.com/cert-manager/cert-manager/internal/apis/config/controller/scheme"
	defaults "github.com/cert-manager/cert-manager/internal/apis/config/controller/v1alpha1"
	"github.com/cert-manager/cert-manager/internal/controller/feature"
	configv1alpha1 "github.com/cert-manager/cert-manager/pkg/apis/config/controller/v1alpha1"
	shimgatewaycontroller "github.com/cert-manager/cert-manager/pkg/controller/certificate-shim/gateways"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

// ControllerFlags defines options that can only be configured via flags.
type ControllerFlags struct {
	// Path to a file containing a ControllerConfiguration resource
	Config string
}

func NewControllerFlags() *ControllerFlags {
	return &ControllerFlags{}
}

func (f *ControllerFlags) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&f.Config, "config", "", "Path to a file containing a ControllerConfiguration object used to configure the controller")
}

func NewControllerConfiguration() (*config.ControllerConfiguration, error) {
	scheme, _, err := configscheme.NewSchemeAndCodecs()
	if err != nil {
		return nil, err
	}
	versioned := &configv1alpha1.ControllerConfiguration{}
	scheme.Default(versioned)
	config := &config.ControllerConfiguration{}
	if err := scheme.Convert(versioned, config, nil); err != nil {
		return nil, err
	}
	return config, nil
}

func AddConfigFlags(fs *pflag.FlagSet, c *config.ControllerConfiguration) {
	fs.StringVar(&c.APIServerHost, "master", c.APIServerHost, ""+
		"Optional apiserver host address to connect to. If not specified, autoconfiguration "+
		"will be attempted.")
	fs.StringVar(&c.KubeConfig, "kubeconfig", c.KubeConfig, ""+
		"Paths to a kubeconfig. Only required if out-of-cluster.")
	fs.Float32Var(&c.KubernetesAPIQPS, "kube-api-qps", c.KubernetesAPIQPS, "indicates the maximum queries-per-second requests to the Kubernetes apiserver")
	fs.IntVar(&c.KubernetesAPIBurst, "kube-api-burst", c.KubernetesAPIBurst, "the maximum burst queries-per-second of requests sent to the Kubernetes apiserver")
	fs.StringVar(&c.ClusterResourceNamespace, "cluster-resource-namespace", c.ClusterResourceNamespace, ""+
		"Namespace to store resources owned by cluster scoped resources such as ClusterIssuer in. "+
		"This must be specified if ClusterIssuers are enabled.")
	fs.StringVar(&c.Namespace, "namespace", c.Namespace, ""+
		"If set, this limits the scope of cert-manager to a single namespace and ClusterIssuers are disabled. "+
		"If not specified, all namespaces will be watched")
	fs.BoolVar(&c.LeaderElectionConfig.Enabled, "leader-elect", c.LeaderElectionConfig.Enabled, ""+
		"If true, cert-manager will perform leader election between instances to ensure no more "+
		"than one instance of cert-manager operates at a time")
	fs.StringVar(&c.LeaderElectionConfig.Namespace, "leader-election-namespace", c.LeaderElectionConfig.Namespace, ""+
		"Namespace used to perform leader election. Only used if leader election is enabled")
	fs.DurationVar(&c.LeaderElectionConfig.LeaseDuration, "leader-election-lease-duration", c.LeaderElectionConfig.LeaseDuration, ""+
		"The duration that non-leader candidates will wait after observing a leadership "+
		"renewal until attempting to acquire leadership of a led but unrenewed leader "+
		"slot. This is effectively the maximum duration that a leader can be stopped "+
		"before it is replaced by another candidate. This is only applicable if leader "+
		"election is enabled.")
	fs.DurationVar(&c.LeaderElectionConfig.RenewDeadline, "leader-election-renew-deadline", c.LeaderElectionConfig.RenewDeadline, ""+
		"The interval between attempts by the acting master to renew a leadership slot "+
		"before it stops leading. This must be less than or equal to the lease duration. "+
		"This is only applicable if leader election is enabled.")
	fs.DurationVar(&c.LeaderElectionConfig.RetryPeriod, "leader-election-retry-period", c.LeaderElectionConfig.RetryPeriod, ""+
		"The duration the clients should wait between attempting acquisition and renewal "+
		"of a leadership. This is only applicable if leader election is enabled.")

	fs.StringSliceVar(&c.Controllers, "controllers", c.Controllers, fmt.Sprintf(""+
		"A list of controllers to enable. '--controllers=*' enables all "+
		"on-by-default controllers, '--controllers=foo' enables just the controller "+
		"named 'foo', '--controllers=*,-foo' disables the controller named "+
		"'foo'.\nAll controllers: %s",
		strings.Join(defaults.AllControllers, ", ")))

	fs.StringVar(&c.ACMEHTTP01Config.SolverImage, "acme-http01-solver-image", c.ACMEHTTP01Config.SolverImage, ""+
		"The docker image to use to solve ACME HTTP01 challenges. You most likely will not "+
		"need to change this parameter unless you are testing a new feature or developing cert-manager.")

	// HTTP-01 solver pod configuration via flags is a now deprecated
	// mechanism - please use pod template instead when adding any new
	// configuration options
	// https://github.com/cert-manager/cert-manager/blob/f1d7c432763100c3fb6eb6a1654d29060b479b3c/pkg/apis/acme/v1/types_issuer.go#L270
	// These flags however will not be deprecated for backwards compatibility purposes.
	fs.StringVar(&c.ACMEHTTP01Config.SolverResourceRequestCPU, "acme-http01-solver-resource-request-cpu", c.ACMEHTTP01Config.SolverResourceRequestCPU, ""+
		"Defines the resource request CPU size when spawning new ACME HTTP01 challenge solver pods.")

	fs.StringVar(&c.ACMEHTTP01Config.SolverResourceRequestMemory, "acme-http01-solver-resource-request-memory", c.ACMEHTTP01Config.SolverResourceRequestMemory, ""+
		"Defines the resource request Memory size when spawning new ACME HTTP01 challenge solver pods.")

	fs.StringVar(&c.ACMEHTTP01Config.SolverResourceLimitsCPU, "acme-http01-solver-resource-limits-cpu", c.ACMEHTTP01Config.SolverResourceLimitsCPU, ""+
		"Defines the resource limits CPU size when spawning new ACME HTTP01 challenge solver pods.")

	fs.StringVar(&c.ACMEHTTP01Config.SolverResourceLimitsMemory, "acme-http01-solver-resource-limits-memory", c.ACMEHTTP01Config.SolverResourceLimitsMemory, ""+
		"Defines the resource limits Memory size when spawning new ACME HTTP01 challenge solver pods.")

	fs.BoolVar(&c.ACMEHTTP01Config.SolverRunAsNonRoot, "acme-http01-solver-run-as-non-root", c.ACMEHTTP01Config.SolverRunAsNonRoot, ""+
		"Defines the ability to run the http01 solver as root for troubleshooting issues")

	fs.StringSliceVar(&c.ACMEHTTP01Config.SolverNameservers, "acme-http01-solver-nameservers",
		c.ACMEHTTP01Config.SolverNameservers, "A list of comma separated dns server endpoints used for "+
			"ACME HTTP01 check requests. This should be a list containing host and "+
			"port, for example 8.8.8.8:53,8.8.4.4:53")

	fs.BoolVar(&c.ClusterIssuerAmbientCredentials, "cluster-issuer-ambient-credentials", c.ClusterIssuerAmbientCredentials, ""+
		"Whether a cluster-issuer may make use of ambient credentials for issuers. 'Ambient Credentials' are credentials drawn from the environment, metadata services, or local files which are not explicitly configured in the ClusterIssuer API object. "+
		"When this flag is enabled, the following sources for credentials are also used: "+
		"AWS - All sources the Go SDK defaults to, notably including any EC2 IAM roles available via instance metadata.")
	fs.BoolVar(&c.IssuerAmbientCredentials, "issuer-ambient-credentials", c.IssuerAmbientCredentials, ""+
		"Whether an issuer may make use of ambient credentials. 'Ambient Credentials' are credentials drawn from the environment, metadata services, or local files which are not explicitly configured in the Issuer API object. "+
		"When this flag is enabled, the following sources for credentials are also used: "+
		"AWS - All sources the Go SDK defaults to, notably including any EC2 IAM roles available via instance metadata.")

	fs.StringSliceVar(&c.IngressShimConfig.DefaultAutoCertificateAnnotations, "auto-certificate-annotations", c.IngressShimConfig.DefaultAutoCertificateAnnotations, ""+
		"The annotation consumed by the ingress-shim controller to indicate an ingress is requesting a certificate")
	fs.StringSliceVar(&c.IngressShimConfig.ExtraCertificateAnnotations, "extra-certificate-annotations", []string{}, ""+
		"Extra annotation to be added by the ingress-shim controller to certificate object")
	fs.StringVar(&c.IngressShimConfig.DefaultIssuerName, "default-issuer-name", c.IngressShimConfig.DefaultIssuerName, ""+
		"Name of the Issuer to use when the tls is requested but issuer name is not specified on the ingress resource.")
	fs.StringVar(&c.IngressShimConfig.DefaultIssuerKind, "default-issuer-kind", c.IngressShimConfig.DefaultIssuerKind, ""+
		"Kind of the Issuer to use when the tls is requested but issuer kind is not specified on the ingress resource.")
	fs.StringVar(&c.IngressShimConfig.DefaultIssuerGroup, "default-issuer-group", c.IngressShimConfig.DefaultIssuerGroup, ""+
		"Group of the Issuer to use when the tls is requested but issuer group is not specified on the ingress resource.")

	fs.StringSliceVar(&c.ACMEDNS01Config.RecursiveNameservers, "dns01-recursive-nameservers",
		c.ACMEDNS01Config.RecursiveNameservers, "A list of comma separated dns server endpoints used for DNS01 and DNS-over-HTTPS (DoH) check requests. "+
			"This should be a list containing entries of the following formats: `<ip address>:<port>` or `https://<DoH RFC 8484 server address>`. "+
			"For example: `8.8.8.8:53,8.8.4.4:53,[2001:4860:4860::8888]:53` or `https://1.1.1.1/dns-query,https://8.8.8.8/dns-query`. "+
			"To make sure ALL DNS requests happen through DoH, `dns01-recursive-nameservers-only` should also be set to true.")
	fs.BoolVar(&c.ACMEDNS01Config.RecursiveNameserversOnly, "dns01-recursive-nameservers-only",
		c.ACMEDNS01Config.RecursiveNameserversOnly,
		"When true, cert-manager will only ever query the configured DNS resolvers "+
			"to perform the ACME DNS01 self check. This is useful in DNS constrained "+
			"environments, where access to authoritative nameservers is restricted. "+
			"Enabling this option could cause the DNS01 self check to take longer "+
			"due to caching performed by the recursive nameservers.")
	fs.DurationVar(&c.ACMEDNS01Config.CheckRetryPeriod, "dns01-check-retry-period", c.ACMEDNS01Config.CheckRetryPeriod, ""+
		"The duration the controller should wait between a propagation check. Despite the name, this flag is used to configure the wait period for both DNS01 and HTTP01 challenge propagation checks. For DNS01 challenges the propagation check verifies that a TXT record with the challenge token has been created. For HTTP01 challenges the propagation check verifies that the challenge token is served at the challenge URL."+
		"This should be a valid duration string, for example 180s or 1h")

	fs.BoolVar(&c.EnableCertificateOwnerRef, "enable-certificate-owner-ref", c.EnableCertificateOwnerRef, ""+
		"Whether to set the certificate resource as an owner of secret where the tls certificate is stored. "+
		"When this flag is enabled, the secret will be automatically removed when the certificate resource is deleted.")
	fs.BoolVar(&c.EnableGatewayAPI, "enable-gateway-api", c.EnableGatewayAPI, ""+
		"Whether gateway API integration is enabled within cert-manager. The ExperimentalGatewayAPISupport "+
		"feature gate must also be enabled (default as of 1.15).")
	fs.StringSliceVar(&c.CopiedAnnotationPrefixes, "copied-annotation-prefixes", c.CopiedAnnotationPrefixes, "Specify which annotations should/shouldn't be copied"+
		"from Certificate to CertificateRequest and Order, as well as from CertificateSigningRequest to Order, by passing a list of annotation key prefixes."+
		"A prefix starting with a dash(-) specifies an annotation that shouldn't be copied. Example: '*,-kubectl.kubernetes.io/'- all annotations"+
		"will be copied apart from the ones where the key is prefixed with 'kubectl.kubernetes.io/'.")
	fs.Var(cliflag.NewMapStringBool(&c.FeatureGates), "feature-gates", "A set of key=value pairs that describe feature gates for alpha/experimental features. "+
		"Options are:\n"+strings.Join(utilfeature.DefaultFeatureGate.KnownFeatures(), "\n"))

	fs.IntVar(&c.NumberOfConcurrentWorkers, "concurrent-workers", c.NumberOfConcurrentWorkers, ""+
		"The number of concurrent workers for each controller.")
	fs.IntVar(&c.MaxConcurrentChallenges, "max-concurrent-challenges", c.MaxConcurrentChallenges, ""+
		"The maximum number of challenges that can be scheduled as 'processing' at once.")

	fs.StringVar(&c.MetricsListenAddress, "metrics-listen-address", c.MetricsListenAddress, ""+
		"The host and port that the metrics endpoint should listen on.")
	fs.BoolVar(&c.EnablePprof, "enable-profiling", c.EnablePprof, ""+
		"Enable profiling for controller.")
	fs.StringVar(&c.PprofAddress, "profiler-address", c.PprofAddress,
		"The host and port that Go profiler should listen on, i.e localhost:6060. Ensure that profiler is not exposed on a public address. Profiler will be served at /debug/pprof.")

	fs.StringVar(&c.MetricsTLSConfig.Filesystem.CertFile, "metrics-tls-cert-file", c.MetricsTLSConfig.Filesystem.CertFile, "path to the file containing the TLS certificate to serve with")
	fs.StringVar(&c.MetricsTLSConfig.Filesystem.KeyFile, "metrics-tls-private-key-file", c.MetricsTLSConfig.Filesystem.KeyFile, "path to the file containing the TLS private key to serve with")

	fs.DurationVar(&c.MetricsTLSConfig.Dynamic.LeafDuration, "metrics-dynamic-serving-leaf-duration", c.MetricsTLSConfig.Dynamic.LeafDuration, "leaf duration of serving certificates")
	fs.StringVar(&c.MetricsTLSConfig.Dynamic.SecretNamespace, "metrics-dynamic-serving-ca-secret-namespace", c.MetricsTLSConfig.Dynamic.SecretNamespace, "namespace of the secret used to store the CA that signs serving certificates")
	fs.StringVar(&c.MetricsTLSConfig.Dynamic.SecretName, "metrics-dynamic-serving-ca-secret-name", c.MetricsTLSConfig.Dynamic.SecretName, "name of the secret used to store the CA that signs serving certificates")
	fs.StringSliceVar(&c.MetricsTLSConfig.Dynamic.DNSNames, "metrics-dynamic-serving-dns-names", c.MetricsTLSConfig.Dynamic.DNSNames, "DNS names that should be present on certificates generated by the dynamic serving CA")
	tlsCipherPossibleValues := cliflag.TLSCipherPossibleValues()
	fs.StringSliceVar(&c.MetricsTLSConfig.CipherSuites, "metrics-tls-cipher-suites", c.MetricsTLSConfig.CipherSuites,
		"Comma-separated list of cipher suites for the server. "+
			"If omitted, the default Go cipher suites will be used.  "+
			"Possible values: "+strings.Join(tlsCipherPossibleValues, ","))
	tlsPossibleVersions := cliflag.TLSPossibleVersions()
	fs.StringVar(&c.MetricsTLSConfig.MinTLSVersion, "metrics-tls-min-version", c.MetricsTLSConfig.MinTLSVersion,
		"Minimum TLS version supported. If omitted, the default Go minimum version will be used. "+
			"Possible values: "+strings.Join(tlsPossibleVersions, ", "))

	// The healthz related flags are given the prefix "internal-" and are hidden,
	// to discourage users from overriding them.
	// We may want to rename or remove these flags when we have feedback from
	// end-users about whether the default liveness
	// probe and the separate healthz server are a good and correct way to
	// mitigate unexpected deadlocks in the controller-manager process.
	//
	// TODO(wallrj) Consider merging the metrics, pprof and healthz servers, and
	// having a single --secure-port flag, like Kubernetes components do.
	fs.StringVar(&c.HealthzListenAddress, "internal-healthz-listen-address", c.HealthzListenAddress, ""+
		"The host and port that the healthz server should listen on. "+
		"The healthz server serves the /livez endpoint, which is called by the LivenessProbe.")
	utilruntime.Must(fs.MarkHidden("internal-healthz-listen-address"))

	fs.DurationVar(&c.LeaderElectionConfig.HealthzTimeout, "internal-healthz-leader-election-timeout", c.LeaderElectionConfig.HealthzTimeout, ""+
		"Leader election healthz checks within this timeout period after the lease expires will still return healthy")
	utilruntime.Must(fs.MarkHidden("internal-healthz-leader-election-timeout"))

	logf.AddFlags(&c.Logging, fs)
}

func EnabledControllers(o *config.ControllerConfiguration) sets.Set[string] {
	var disabled []string
	enabled := sets.New[string]()

	for _, controller := range o.Controllers {
		switch {
		case controller == "*":
			enabled = enabled.Insert(defaults.DefaultEnabledControllers...)
		case strings.HasPrefix(controller, "-"):
			disabled = append(disabled, strings.TrimPrefix(controller, "-"))
		default:
			enabled = enabled.Insert(controller)
		}
	}

	// Detect if "*" was implied (in case only disabled controllers were specified)
	if len(disabled) > 0 && len(enabled) == 0 {
		enabled = enabled.Insert(defaults.DefaultEnabledControllers...)
	}

	if utilfeature.DefaultFeatureGate.Enabled(feature.ExperimentalCertificateSigningRequestControllers) {
		logf.Log.Info("enabling all experimental certificatesigningrequest controllers")
		enabled = enabled.Insert(defaults.ExperimentalCertificateSigningRequestControllers...)
	}

	if utilfeature.DefaultFeatureGate.Enabled(feature.ExperimentalGatewayAPISupport) && o.EnableGatewayAPI {
		logf.Log.Info("enabling the sig-network Gateway API certificate-shim and HTTP-01 solver")
		enabled = enabled.Insert(shimgatewaycontroller.ControllerName)
	}

	if utilfeature.DefaultFeatureGate.Enabled(feature.ValidateCAA) {
		logf.Log.Info("the ValidateCAA feature flag has been removed and is now a no-op")
	}

	// If running namespaced, remove all cluster-scoped controllers.
	if o.Namespace != "" {
		logf.Log.Info("disabling all cluster-scoped controllers as cert-manager is scoped to a single namespace",
			"controllers", strings.Join(defaults.ClusterScopedControllers, ", "))
		enabled = enabled.Delete(defaults.ClusterScopedControllers...)
	}

	// Only after all controllers have been added, remove the disabled ones.
	enabled = enabled.Delete(disabled...)

	return enabled
}
