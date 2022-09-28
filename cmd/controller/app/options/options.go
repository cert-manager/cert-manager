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
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"

	cmdutil "github.com/cert-manager/cert-manager/cmd/util"
	"github.com/cert-manager/cert-manager/internal/controller/feature"
	cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	challengescontroller "github.com/cert-manager/cert-manager/pkg/controller/acmechallenges"
	orderscontroller "github.com/cert-manager/cert-manager/pkg/controller/acmeorders"
	shimgatewaycontroller "github.com/cert-manager/cert-manager/pkg/controller/certificate-shim/gateways"
	shimingresscontroller "github.com/cert-manager/cert-manager/pkg/controller/certificate-shim/ingresses"
	cracmecontroller "github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/acme"
	crapprovercontroller "github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/approver"
	crcacontroller "github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/ca"
	crselfsignedcontroller "github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/selfsigned"
	crvaultcontroller "github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/vault"
	crvenaficontroller "github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/venafi"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/issuing"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/keymanager"
	certificatesmetricscontroller "github.com/cert-manager/cert-manager/pkg/controller/certificates/metrics"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/readiness"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/requestmanager"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/revisionmanager"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/trigger"
	csracmecontroller "github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/acme"
	csrcacontroller "github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/ca"
	csrselfsignedcontroller "github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/selfsigned"
	csrvaultcontroller "github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/vault"
	csrvenaficontroller "github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/venafi"
	clusterissuerscontroller "github.com/cert-manager/cert-manager/pkg/controller/clusterissuers"
	issuerscontroller "github.com/cert-manager/cert-manager/pkg/controller/issuers"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
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

	controllers []string

	ACMEHTTP01SolverImage                 string
	ACMEHTTP01SolverResourceRequestCPU    string
	ACMEHTTP01SolverResourceRequestMemory string
	ACMEHTTP01SolverResourceLimitsCPU     string
	ACMEHTTP01SolverResourceLimitsMemory  string
	// Allows specifying a list of custom nameservers to perform HTTP01 checks on.
	ACMEHTTP01SolverNameservers []string

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
	// PprofAddress is the address on which Go profiler will run. Should be
	// in form <host>:<port>.
	PprofAddress string
	// EnablePprof determines whether pprof should be enabled.
	EnablePprof bool

	// DNSO1CheckRetryPeriod is the period of time after which to check if
	// challenge URL can be reached by cert-manager controller. This is used
	// for both DNS-01 and HTTP-01 challenges.
	DNS01CheckRetryPeriod time.Duration

	// Annotations copied Certificate -> CertificateRequest,
	// CertificateRequest -> Order. Slice of string literals that are
	// treated as prefixes for annotation keys.
	CopiedAnnotationPrefixes []string
}

const (
	defaultAPIServerHost              = ""
	defaultKubeconfig                 = ""
	defaultKubernetesAPIQPS   float32 = 20
	defaultKubernetesAPIBurst         = 50

	defaultClusterResourceNamespace = "kube-system"
	defaultNamespace                = ""

	defaultClusterIssuerAmbientCredentials = true
	defaultIssuerAmbientCredentials        = false

	defaultTLSACMEIssuerName         = ""
	defaultTLSACMEIssuerKind         = "Issuer"
	defaultTLSACMEIssuerGroup        = cm.GroupName
	defaultEnableCertificateOwnerRef = false

	defaultDNS01RecursiveNameserversOnly = false

	defaultMaxConcurrentChallenges = 60

	defaultPrometheusMetricsServerAddress = "0.0.0.0:9402"

	// default time period to wait between checking DNS01 and HTTP01 challenge propagation
	defaultDNS01CheckRetryPeriod = 10 * time.Second
)

var (
	defaultACMEHTTP01SolverImage                 = fmt.Sprintf("quay.io/jetstack/cert-manager-acmesolver:%s", util.AppVersion)
	defaultACMEHTTP01SolverResourceRequestCPU    = "10m"
	defaultACMEHTTP01SolverResourceRequestMemory = "64Mi"
	defaultACMEHTTP01SolverResourceLimitsCPU     = "100m"
	defaultACMEHTTP01SolverResourceLimitsMemory  = "64Mi"

	defaultAutoCertificateAnnotations = []string{"kubernetes.io/tls-acme"}

	allControllers = []string{
		issuerscontroller.ControllerName,
		clusterissuerscontroller.ControllerName,
		certificatesmetricscontroller.ControllerName,
		shimingresscontroller.ControllerName,
		shimgatewaycontroller.ControllerName,
		orderscontroller.ControllerName,
		challengescontroller.ControllerName,
		cracmecontroller.CRControllerName,
		crapprovercontroller.ControllerName,
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
		revisionmanager.ControllerName,
	}

	defaultEnabledControllers = []string{
		issuerscontroller.ControllerName,
		clusterissuerscontroller.ControllerName,
		certificatesmetricscontroller.ControllerName,
		shimingresscontroller.ControllerName,
		orderscontroller.ControllerName,
		challengescontroller.ControllerName,
		cracmecontroller.CRControllerName,
		crapprovercontroller.ControllerName,
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
		revisionmanager.ControllerName,
	}

	experimentalCertificateSigningRequestControllers = []string{
		csracmecontroller.CSRControllerName,
		csrcacontroller.CSRControllerName,
		csrselfsignedcontroller.CSRControllerName,
		csrvenaficontroller.CSRControllerName,
		csrvaultcontroller.CSRControllerName,
	}
	// Annotations that will be copied from Certificate to CertificateRequest and to Order.
	// By default, copy all annotations except for the ones applied by kubectl, fluxcd, argocd.
	defaultCopiedAnnotationPrefixes = []string{
		"*",
		"-kubectl.kubernetes.io/",
		"-fluxcd.io/",
		"-argocd.argoproj.io/",
	}
)

func NewControllerOptions() *ControllerOptions {
	return &ControllerOptions{
		APIServerHost:                     defaultAPIServerHost,
		ClusterResourceNamespace:          defaultClusterResourceNamespace,
		KubernetesAPIQPS:                  defaultKubernetesAPIQPS,
		KubernetesAPIBurst:                defaultKubernetesAPIBurst,
		Namespace:                         defaultNamespace,
		LeaderElect:                       cmdutil.DefaultLeaderElect,
		LeaderElectionNamespace:           cmdutil.DefaultLeaderElectionNamespace,
		LeaderElectionLeaseDuration:       cmdutil.DefaultLeaderElectionLeaseDuration,
		LeaderElectionRenewDeadline:       cmdutil.DefaultLeaderElectionRenewDeadline,
		LeaderElectionRetryPeriod:         cmdutil.DefaultLeaderElectionRetryPeriod,
		controllers:                       defaultEnabledControllers,
		ClusterIssuerAmbientCredentials:   defaultClusterIssuerAmbientCredentials,
		IssuerAmbientCredentials:          defaultIssuerAmbientCredentials,
		DefaultIssuerName:                 defaultTLSACMEIssuerName,
		DefaultIssuerKind:                 defaultTLSACMEIssuerKind,
		DefaultIssuerGroup:                defaultTLSACMEIssuerGroup,
		DefaultAutoCertificateAnnotations: defaultAutoCertificateAnnotations,
		ACMEHTTP01SolverNameservers:       []string{},
		DNS01RecursiveNameservers:         []string{},
		DNS01RecursiveNameserversOnly:     defaultDNS01RecursiveNameserversOnly,
		EnableCertificateOwnerRef:         defaultEnableCertificateOwnerRef,
		MetricsListenAddress:              defaultPrometheusMetricsServerAddress,
		DNS01CheckRetryPeriod:             defaultDNS01CheckRetryPeriod,
		EnablePprof:                       cmdutil.DefaultEnableProfiling,
		PprofAddress:                      cmdutil.DefaultProfilerAddr,
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
	fs.BoolVar(&s.LeaderElect, "leader-elect", cmdutil.DefaultLeaderElect, ""+
		"If true, cert-manager will perform leader election between instances to ensure no more "+
		"than one instance of cert-manager operates at a time")
	fs.StringVar(&s.LeaderElectionNamespace, "leader-election-namespace", cmdutil.DefaultLeaderElectionNamespace, ""+
		"Namespace used to perform leader election. Only used if leader election is enabled")
	fs.DurationVar(&s.LeaderElectionLeaseDuration, "leader-election-lease-duration", cmdutil.DefaultLeaderElectionLeaseDuration, ""+
		"The duration that non-leader candidates will wait after observing a leadership "+
		"renewal until attempting to acquire leadership of a led but unrenewed leader "+
		"slot. This is effectively the maximum duration that a leader can be stopped "+
		"before it is replaced by another candidate. This is only applicable if leader "+
		"election is enabled.")
	fs.DurationVar(&s.LeaderElectionRenewDeadline, "leader-election-renew-deadline", cmdutil.DefaultLeaderElectionRenewDeadline, ""+
		"The interval between attempts by the acting master to renew a leadership slot "+
		"before it stops leading. This must be less than or equal to the lease duration. "+
		"This is only applicable if leader election is enabled.")
	fs.DurationVar(&s.LeaderElectionRetryPeriod, "leader-election-retry-period", cmdutil.DefaultLeaderElectionRetryPeriod, ""+
		"The duration the clients should wait between attempting acquisition and renewal "+
		"of a leadership. This is only applicable if leader election is enabled.")

	fs.StringSliceVar(&s.controllers, "controllers", []string{"*"}, fmt.Sprintf(""+
		"A list of controllers to enable. '--controllers=*' enables all "+
		"on-by-default controllers, '--controllers=foo' enables just the controller "+
		"named 'foo', '--controllers=*,-foo' disables the controller named "+
		"'foo'.\nAll controllers: %s",
		strings.Join(allControllers, ", ")))

	// HTTP-01 solver pod configuration via flags is a now deprecated
	// mechanism- please use pod template instead when adding any new
	// configuration options
	// https://github.com/cert-manager/cert-manager/blob/f1d7c432763100c3fb6eb6a1654d29060b479b3c/pkg/apis/acme/v1/types_issuer.go#L270
	// These flags however will not be deprecated for backwards compatibility purposes.
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

	fs.StringSliceVar(&s.ACMEHTTP01SolverNameservers, "acme-http01-solver-nameservers",
		[]string{}, "A list of comma separated dns server endpoints used for "+
			"ACME HTTP01 check requests. This should be a list containing host and "+
			"port, for example 8.8.8.8:53,8.8.4.4:53")

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

	fs.BoolVar(&s.EnableCertificateOwnerRef, "enable-certificate-owner-ref", defaultEnableCertificateOwnerRef, ""+
		"Whether to set the certificate resource as an owner of secret where the tls certificate is stored. "+
		"When this flag is enabled, the secret will be automatically removed when the certificate resource is deleted.")
	fs.StringSliceVar(&s.CopiedAnnotationPrefixes, "copied-annotation-prefixes", defaultCopiedAnnotationPrefixes, "Specify which annotations should/shouldn't be copied"+
		"from Certificate to CertificateRequest and Order, as well as from CertificateSigningRequest to Order, by passing a list of annotation key prefixes."+
		"A prefix starting with a dash(-) specifies an annotation that shouldn't be copied. Example: '*,-kubectl.kuberenetes.io/'- all annotations"+
		"will be copied apart from the ones where the key is prefixed with 'kubectl.kubernetes.io/'.")

	fs.IntVar(&s.MaxConcurrentChallenges, "max-concurrent-challenges", defaultMaxConcurrentChallenges, ""+
		"The maximum number of challenges that can be scheduled as 'processing' at once.")
	fs.DurationVar(&s.DNS01CheckRetryPeriod, "dns01-check-retry-period", defaultDNS01CheckRetryPeriod, ""+
		"The duration the controller should wait between a propagation check. Despite the name, this flag is used to configure the wait period for both DNS01 and HTTP01 challenge propagation checks. For DNS01 challenges the propagation check verifies that a TXT record with the challenge token has been created. For HTTP01 challenges the propagation check verifies that the challenge token is served at the challenge URL."+
		"This should be a valid duration string, for example 180s or 1h")

	fs.StringVar(&s.MetricsListenAddress, "metrics-listen-address", defaultPrometheusMetricsServerAddress, ""+
		"The host and port that the metrics endpoint should listen on.")
	fs.BoolVar(&s.EnablePprof, "enable-profiling", cmdutil.DefaultEnableProfiling, ""+
		"Enable profiling for controller.")
	fs.StringVar(&s.PprofAddress, "profiler-address", cmdutil.DefaultProfilerAddr,
		"The host and port that Go profiler should listen on, i.e localhost:6060. Ensure that profiler is not exposed on a public address. Profiler will be served at /debug/pprof.")
}

func (o *ControllerOptions) Validate() error {
	if len(o.DefaultIssuerKind) == 0 {
		return errors.New("the --default-issuer-kind flag must not be empty")
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

	for _, server := range append(o.DNS01RecursiveNameservers, o.ACMEHTTP01SolverNameservers...) {
		// ensure all servers have a port number
		_, _, err := net.SplitHostPort(server)
		if err != nil {
			return fmt.Errorf("invalid DNS server (%v): %v", err, server)
		}
	}

	errs := []error{}
	allControllersSet := sets.NewString(allControllers...)
	for _, controller := range o.controllers {
		if controller == "*" {
			continue
		}

		controller = strings.TrimPrefix(controller, "-")
		if !allControllersSet.Has(controller) {
			errs = append(errs, fmt.Errorf("%q is not in the list of known controllers", controller))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("validation failed for '--controllers': %v", errs)
	}

	return nil
}

func (o *ControllerOptions) EnabledControllers() sets.String {
	var disabled []string
	enabled := sets.NewString()

	for _, controller := range o.controllers {
		switch {
		case controller == "*":
			enabled = enabled.Insert(defaultEnabledControllers...)
		case strings.HasPrefix(controller, "-"):
			disabled = append(disabled, strings.TrimPrefix(controller, "-"))
		default:
			enabled = enabled.Insert(controller)
		}
	}

	enabled = enabled.Delete(disabled...)

	if utilfeature.DefaultFeatureGate.Enabled(feature.ExperimentalCertificateSigningRequestControllers) {
		logf.Log.Info("enabling all experimental certificatesigningrequest controllers")
		enabled = enabled.Insert(experimentalCertificateSigningRequestControllers...)
	}

	if utilfeature.DefaultFeatureGate.Enabled(feature.ExperimentalGatewayAPISupport) {
		logf.Log.Info("enabling the sig-network Gateway API certificate-shim and HTTP-01 solver")
		enabled = enabled.Insert(shimgatewaycontroller.ControllerName)
	}

	return enabled
}
