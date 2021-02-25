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
	"net"
	"time"

	"github.com/spf13/pflag"

	cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	challengescontroller "github.com/cert-manager/cert-manager/pkg/controller/acmechallenges"
	orderscontroller "github.com/cert-manager/cert-manager/pkg/controller/acmeorders"
	cracmecontroller "github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/acme"
	crcacontroller "github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/ca"
	crselfsignedcontroller "github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/selfsigned"
	crvaultcontroller "github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/vault"
	crvenaficontroller "github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/venafi"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/issuing"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/keymanager"
	certificatesmetricscontroller "github.com/cert-manager/cert-manager/pkg/controller/certificates/metrics"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/readiness"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/requestmanager"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/trigger"
	clusterissuerscontroller "github.com/cert-manager/cert-manager/pkg/controller/clusterissuers"
	ingressshimcontroller "github.com/cert-manager/cert-manager/pkg/controller/ingress-shim"
	issuerscontroller "github.com/cert-manager/cert-manager/pkg/controller/issuers"
	"github.com/cert-manager/cert-manager/pkg/util"
)

type ControllerOptions struct {
	APIServerHost      string
	Kubeconfig         string
	KubernetesAPIQPS   float32
	KubernetesAPIBurst int

	ClusterResourceNamespace string
	Namespace                string

	LeaderElect                 bool
	LeaderElectionNamespace     string
	LeaderElectionLeaseDuration time.Duration
	LeaderElectionRenewDeadline time.Duration
	LeaderElectionRetryPeriod   time.Duration

	EnabledControllers []string

	ACMEHTTP01SolverImage                 string
	ACMEHTTP01SolverResourceRequestCPU    string
	ACMEHTTP01SolverResourceRequestMemory string
	ACMEHTTP01SolverResourceLimitsCPU     string
	ACMEHTTP01SolverResourceLimitsMemory  string

	ClusterIssuerAmbientCredentials bool
	IssuerAmbientCredentials        bool

	// Default issuer/certificates details consumed by ingress-shim
	DefaultIssuerName                 string
	DefaultIssuerKind                 string
	DefaultIssuerGroup                string
	DefaultAutoCertificateAnnotations []string

	// Allows specifying a list of custom nameservers to perform DNS checks on.
	DNS01RecursiveNameservers []string
	// Allows controlling if recursive nameservers are only used for all checks.
	// Normally authoritative nameservers are used for checking propagation.
	DNS01RecursiveNameserversOnly bool

	EnableCertificateOwnerRef bool

	MaxConcurrentChallenges int

	// The host and port address, separated by a ':', that the Prometheus server
	// should expose metrics on.
	MetricsListenAddress string
	// EnablePprof controls whether net/http/pprof handlers are registered with
	// the HTTP listener.
	EnablePprof bool

	DNS01CheckRetryPeriod time.Duration
}

const (
	defaultAPIServerHost              = ""
	defaultKubeconfig                 = ""
	defaultKubernetesAPIQPS   float32 = 20
	defaultKubernetesAPIBurst         = 50

	defaultClusterResourceNamespace = "kube-system"
	defaultNamespace                = ""

	defaultLeaderElect                 = true
	defaultLeaderElectionNamespace     = "kube-system"
	defaultLeaderElectionLeaseDuration = 60 * time.Second
	defaultLeaderElectionRenewDeadline = 40 * time.Second
	defaultLeaderElectionRetryPeriod   = 15 * time.Second

	defaultClusterIssuerAmbientCredentials = true
	defaultIssuerAmbientCredentials        = false

	defaultTLSACMEIssuerName         = ""
	defaultTLSACMEIssuerKind         = "Issuer"
	defaultTLSACMEIssuerGroup        = cm.GroupName
	defaultEnableCertificateOwnerRef = false

	defaultDNS01RecursiveNameserversOnly = false

	defaultMaxConcurrentChallenges = 60

	defaultPrometheusMetricsServerAddress = "0.0.0.0:9402"

	defaultDNS01CheckRetryPeriod = 10 * time.Second
)

var (
	defaultACMEHTTP01SolverImage                 = fmt.Sprintf("quay.io/jetstack/cert-manager-acmesolver:%s", util.AppVersion)
	defaultACMEHTTP01SolverResourceRequestCPU    = "10m"
	defaultACMEHTTP01SolverResourceRequestMemory = "64Mi"
	defaultACMEHTTP01SolverResourceLimitsCPU     = "100m"
	defaultACMEHTTP01SolverResourceLimitsMemory  = "64Mi"

	defaultAutoCertificateAnnotations = []string{"kubernetes.io/tls-acme"}

	defaultEnabledControllers = []string{
		issuerscontroller.ControllerName,
		clusterissuerscontroller.ControllerName,
		certificatesmetricscontroller.ControllerName,
		ingressshimcontroller.ControllerName,
		orderscontroller.ControllerName,
		challengescontroller.ControllerName,
		cracmecontroller.CRControllerName,
		crcacontroller.CRControllerName,
		crselfsignedcontroller.CRControllerName,
		crvaultcontroller.CRControllerName,
		crvenaficontroller.CRControllerName,
		// certificate controllers
		trigger.ControllerName,
		issuing.ControllerName,
		keymanager.ControllerName,
		requestmanager.ControllerName,
		readiness.ControllerName,
	}
)

func NewControllerOptions() *ControllerOptions {
	return &ControllerOptions{
		APIServerHost:                     defaultAPIServerHost,
		ClusterResourceNamespace:          defaultClusterResourceNamespace,
		KubernetesAPIQPS:                  defaultKubernetesAPIQPS,
		KubernetesAPIBurst:                defaultKubernetesAPIBurst,
		Namespace:                         defaultNamespace,
		LeaderElect:                       defaultLeaderElect,
		LeaderElectionNamespace:           defaultLeaderElectionNamespace,
		LeaderElectionLeaseDuration:       defaultLeaderElectionLeaseDuration,
		LeaderElectionRenewDeadline:       defaultLeaderElectionRenewDeadline,
		LeaderElectionRetryPeriod:         defaultLeaderElectionRetryPeriod,
		EnabledControllers:                defaultEnabledControllers,
		ClusterIssuerAmbientCredentials:   defaultClusterIssuerAmbientCredentials,
		IssuerAmbientCredentials:          defaultIssuerAmbientCredentials,
		DefaultIssuerName:                 defaultTLSACMEIssuerName,
		DefaultIssuerKind:                 defaultTLSACMEIssuerKind,
		DefaultIssuerGroup:                defaultTLSACMEIssuerGroup,
		DefaultAutoCertificateAnnotations: defaultAutoCertificateAnnotations,
		DNS01RecursiveNameservers:         []string{},
		DNS01RecursiveNameserversOnly:     defaultDNS01RecursiveNameserversOnly,
		EnableCertificateOwnerRef:         defaultEnableCertificateOwnerRef,
		MetricsListenAddress:              defaultPrometheusMetricsServerAddress,
		DNS01CheckRetryPeriod:             defaultDNS01CheckRetryPeriod,
		EnablePprof:                       false,
	}
}

func (s *ControllerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&s.APIServerHost, "master", defaultAPIServerHost, ""+
		"Optional apiserver host address to connect to. If not specified, autoconfiguration "+
		"will be attempted.")
	fs.StringVar(&s.Kubeconfig, "kubeconfig", defaultKubeconfig, ""+
		"Paths to a kubeconfig. Only required if out-of-cluster.")
	fs.Float32Var(&s.KubernetesAPIQPS, "kube-api-qps", defaultKubernetesAPIQPS, "indicates the maximum queries-per-second requests to the Kubernetes apiserver")
	fs.IntVar(&s.KubernetesAPIBurst, "kube-api-burst", defaultKubernetesAPIBurst, "the maximum burst queries-per-second of requests sent to the Kubernetes apiserver")
	fs.StringVar(&s.ClusterResourceNamespace, "cluster-resource-namespace", defaultClusterResourceNamespace, ""+
		"Namespace to store resources owned by cluster scoped resources such as ClusterIssuer in. "+
		"This must be specified if ClusterIssuers are enabled.")
	fs.StringVar(&s.Namespace, "namespace", defaultNamespace, ""+
		"If set, this limits the scope of cert-manager to a single namespace and ClusterIssuers are disabled. "+
		"If not specified, all namespaces will be watched")
	fs.BoolVar(&s.LeaderElect, "leader-elect", true, ""+
		"If true, cert-manager will perform leader election between instances to ensure no more "+
		"than one instance of cert-manager operates at a time")
	fs.StringVar(&s.LeaderElectionNamespace, "leader-election-namespace", defaultLeaderElectionNamespace, ""+
		"Namespace used to perform leader election. Only used if leader election is enabled")
	fs.DurationVar(&s.LeaderElectionLeaseDuration, "leader-election-lease-duration", defaultLeaderElectionLeaseDuration, ""+
		"The duration that non-leader candidates will wait after observing a leadership "+
		"renewal until attempting to acquire leadership of a led but unrenewed leader "+
		"slot. This is effectively the maximum duration that a leader can be stopped "+
		"before it is replaced by another candidate. This is only applicable if leader "+
		"election is enabled.")
	fs.DurationVar(&s.LeaderElectionRenewDeadline, "leader-election-renew-deadline", defaultLeaderElectionRenewDeadline, ""+
		"The interval between attempts by the acting master to renew a leadership slot "+
		"before it stops leading. This must be less than or equal to the lease duration. "+
		"This is only applicable if leader election is enabled.")
	fs.DurationVar(&s.LeaderElectionRetryPeriod, "leader-election-retry-period", defaultLeaderElectionRetryPeriod, ""+
		"The duration the clients should wait between attempting acquisition and renewal "+
		"of a leadership. This is only applicable if leader election is enabled.")

	fs.StringSliceVar(&s.EnabledControllers, "controllers", defaultEnabledControllers, ""+
		"The set of controllers to enable.")

	fs.StringVar(&s.ACMEHTTP01SolverImage, "acme-http01-solver-image", defaultACMEHTTP01SolverImage, ""+
		"The docker image to use to solve ACME HTTP01 challenges. You most likely will not "+
		"need to change this parameter unless you are testing a new feature or developing cert-manager.")

	fs.StringVar(&s.ACMEHTTP01SolverResourceRequestCPU, "acme-http01-solver-resource-request-cpu", defaultACMEHTTP01SolverResourceRequestCPU, ""+
		"Defines the resource request CPU size when spawning new ACME HTTP01 challenge solver pods.")

	fs.StringVar(&s.ACMEHTTP01SolverResourceRequestMemory, "acme-http01-solver-resource-request-memory", defaultACMEHTTP01SolverResourceRequestMemory, ""+
		"Defines the resource request Memory size when spawning new ACME HTTP01 challenge solver pods.")

	fs.StringVar(&s.ACMEHTTP01SolverResourceLimitsCPU, "acme-http01-solver-resource-limits-cpu", defaultACMEHTTP01SolverResourceLimitsCPU, ""+
		"Defines the resource limits CPU size when spawning new ACME HTTP01 challenge solver pods.")

	fs.StringVar(&s.ACMEHTTP01SolverResourceLimitsMemory, "acme-http01-solver-resource-limits-memory", defaultACMEHTTP01SolverResourceLimitsMemory, ""+
		"Defines the resource limits Memory size when spawning new ACME HTTP01 challenge solver pods.")

	fs.BoolVar(&s.ClusterIssuerAmbientCredentials, "cluster-issuer-ambient-credentials", defaultClusterIssuerAmbientCredentials, ""+
		"Whether a cluster-issuer may make use of ambient credentials for issuers. 'Ambient Credentials' are credentials drawn from the environment, metadata services, or local files which are not explicitly configured in the ClusterIssuer API object. "+
		"When this flag is enabled, the following sources for credentials are also used: "+
		"AWS - All sources the Go SDK defaults to, notably including any EC2 IAM roles available via instance metadata.")
	fs.BoolVar(&s.IssuerAmbientCredentials, "issuer-ambient-credentials", defaultIssuerAmbientCredentials, ""+
		"Whether an issuer may make use of ambient credentials. 'Ambient Credentials' are credentials drawn from the environment, metadata services, or local files which are not explicitly configured in the Issuer API object. "+
		"When this flag is enabled, the following sources for credentials are also used: "+
		"AWS - All sources the Go SDK defaults to, notably including any EC2 IAM roles available via instance metadata.")
	fs.StringSliceVar(&s.DefaultAutoCertificateAnnotations, "auto-certificate-annotations", defaultAutoCertificateAnnotations, ""+
		"The annotation consumed by the ingress-shim controller to indicate a ingress is requesting a certificate")

	fs.StringVar(&s.DefaultIssuerName, "default-issuer-name", defaultTLSACMEIssuerName, ""+
		"Name of the Issuer to use when the tls is requested but issuer name is not specified on the ingress resource.")
	fs.StringVar(&s.DefaultIssuerKind, "default-issuer-kind", defaultTLSACMEIssuerKind, ""+
		"Kind of the Issuer to use when the tls is requested but issuer kind is not specified on the ingress resource.")
	fs.StringVar(&s.DefaultIssuerGroup, "default-issuer-group", defaultTLSACMEIssuerGroup, ""+
		"Group of the Issuer to use when the tls is requested but issuer group is not specified on the ingress resource.")
	fs.StringSliceVar(&s.DNS01RecursiveNameservers, "dns01-recursive-nameservers",
		[]string{}, "A list of comma separated dns server endpoints used for "+
			"DNS01 check requests. This should be a list containing host and "+
			"port, for example 8.8.8.8:53,8.8.4.4:53")
	fs.BoolVar(&s.DNS01RecursiveNameserversOnly, "dns01-recursive-nameservers-only",
		defaultDNS01RecursiveNameserversOnly,
		"When true, cert-manager will only ever query the configured DNS resolvers "+
			"to perform the ACME DNS01 self check. This is useful in DNS constrained "+
			"environments, where access to authoritative nameservers is restricted. "+
			"Enabling this option could cause the DNS01 self check to take longer "+
			"due to caching performed by the recursive nameservers.")
	fs.StringSliceVar(&s.DNS01RecursiveNameservers, "dns01-self-check-nameservers",
		[]string{}, "A list of comma separated dns server endpoints used for "+
			"DNS01 check requests. This should be a list containing host and port, "+
			"for example 8.8.8.8:53,8.8.4.4:53")
	fs.MarkDeprecated("dns01-self-check-nameservers", "Deprecated in favour of dns01-recursive-nameservers")
	fs.BoolVar(&s.EnableCertificateOwnerRef, "enable-certificate-owner-ref", defaultEnableCertificateOwnerRef, ""+
		"Whether to set the certificate resource as an owner of secret where the tls certificate is stored. "+
		"When this flag is enabled, the secret will be automatically removed when the certificate resource is deleted.")
	fs.IntVar(&s.MaxConcurrentChallenges, "max-concurrent-challenges", defaultMaxConcurrentChallenges, ""+
		"The maximum number of challenges that can be scheduled as 'processing' at once.")
	fs.DurationVar(&s.DNS01CheckRetryPeriod, "dns01-check-retry-period", defaultDNS01CheckRetryPeriod, ""+
		"The duration the controller should wait between checking if a ACME dns entry exists."+
		"This should be a valid duration string, for example 180s or 1h")

	fs.StringVar(&s.MetricsListenAddress, "metrics-listen-address", defaultPrometheusMetricsServerAddress, ""+
		"The host and port that the metrics endpoint should listen on.")
	fs.BoolVar(&s.EnablePprof, "enable-profiling", false, ""+
		"Enable profiling for controller.")
}

func (o *ControllerOptions) Validate() error {
	switch o.DefaultIssuerKind {
	case "Issuer":
	case "ClusterIssuer":
	default:
		return fmt.Errorf("invalid default issuer kind: %v", o.DefaultIssuerKind)
	}

	if o.KubernetesAPIBurst <= 0 {
		return fmt.Errorf("invalid value for kube-api-burst: %v must be higher than 0", o.KubernetesAPIBurst)
	}

	if o.KubernetesAPIQPS <= 0 {
		return fmt.Errorf("invalid value for kube-api-qps: %v must be higher than 0", o.KubernetesAPIQPS)
	}

	if float32(o.KubernetesAPIBurst) < o.KubernetesAPIQPS {
		return fmt.Errorf("invalid value for kube-api-burst: %v must be higher or equal to kube-api-qps: %v", o.KubernetesAPIQPS, o.KubernetesAPIQPS)
	}

	for _, server := range o.DNS01RecursiveNameservers {
		// ensure all servers have a port number
		_, _, err := net.SplitHostPort(server)
		if err != nil {
			return fmt.Errorf("invalid DNS server (%v): %v", err, server)
		}
	}

	return nil
}
