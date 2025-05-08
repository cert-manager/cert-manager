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

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	clientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/utils/clock"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
	gwclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gwscheme "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/scheme"
	gwinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	"github.com/cert-manager/cert-manager/internal/kube"
	"github.com/cert-manager/cert-manager/pkg/acme/accounts"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	clientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cmscheme "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/scheme"
	informers "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	"github.com/cert-manager/cert-manager/pkg/util"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

// This sets the informer's resync period to 10 hours
// following the controller-runtime defaults
// and following discussion: https://github.com/kubernetes-sigs/controller-runtime/pull/88#issuecomment-408500629
const resyncPeriod = 10 * time.Hour

// Context contains various types that are used by controller implementations.
// We purposely don't have specific informers/listers here, and instead keep a
// reference to a SharedInformerFactory so that controllers can choose
// themselves which listers are required.
// Each component should be given distinct Contexts, built from the
// ContextFactory that has configured the underlying client to use separate
// User Agents.
type Context struct {
	// RootContext is the root context for the controller
	RootContext context.Context

	// FieldManager is the string that should be used as the field manager when
	// applying API object. This value is derived from the user agent.
	FieldManager string
	// RESTConfig is the loaded Kubernetes apiserver rest client configuration
	RESTConfig *rest.Config
	// Scheme is the Kubernetes scheme that should be used when serialising and
	// deserialising API objects
	Scheme *runtime.Scheme
	// Client is a Kubernetes clientset
	Client kubernetes.Interface
	// CMClient is a cert-manager clientset
	CMClient clientset.Interface
	// GWClient is a GatewayAPI clientset.
	GWClient gwclient.Interface
	// MetadataClient is a PartialObjectMetadata client
	MetadataClient metadata.Interface
	// DiscoveryClient is a discovery interface. Usually set to Client.Discovery unless a fake client is in use.
	DiscoveryClient discovery.DiscoveryInterface

	// Recorder to record events to
	Recorder record.EventRecorder

	// KubeSharedInformerFactory can be used to obtain shared
	// SharedIndexInformer instances for Kubernetes types
	KubeSharedInformerFactory internalinformers.KubeInformerFactory

	// SharedInformerFactory can be used to obtain shared SharedIndexInformer
	// instances for cert-manager.io types
	SharedInformerFactory informers.SharedInformerFactory

	// HTTP01ResourceMetadataInformersFactory is a metadata only informers
	// factory with a http-01 resource label filter selector
	HTTP01ResourceMetadataInformersFactory metadatainformer.SharedInformerFactory

	// GWShared can be used to obtain SharedIndexInformer instances for
	// gateway.networking.k8s.io types
	GWShared             gwinformers.SharedInformerFactory
	GatewaySolverEnabled bool

	ContextOptions
}

// ContextOptions are static Controller Context options.
type ContextOptions struct {
	// APIServerHost is the host address of the target Kubernetes API server.
	APIServerHost string

	// Kubeconfig is the optional file path location to a kubeconfig to connect
	// and authenticate to the API server.
	Kubeconfig string

	// Kubernetes API QPS is the value of the maximum QPS to the API server from
	// clients.
	KubernetesAPIQPS float32

	// KubernetesAPIBurst is the value of the Maximum burst for throttle.
	KubernetesAPIBurst int

	// Namespace is the namespace to operate within.
	// If unset, operates on all namespaces
	Namespace string

	// Clock should be used to access the current time instead of relying on
	// time.Now, to make it easier to test controllers that utilise time
	Clock clock.Clock

	// Metrics is used for exposing Prometheus metrics across the controllers
	Metrics *metrics.Metrics

	IssuerOptions
	ACMEOptions
	IngressShimOptions
	CertificateOptions
	SchedulerOptions
	ConfigOptions
}

type ConfigOptions struct {
	// EnableGatewayAPI indicates if the user has enabled GatewayAPI support.
	EnableGatewayAPI bool
}

type IssuerOptions struct {
	// ClusterResourceNamespace is the namespace to store resources created by
	// non-namespaced resources (e.g., ClusterIssuer) in.
	ClusterResourceNamespace string

	// ClusterIssuerAmbientCredentials controls whether a cluster issuer should
	// pick up ambient credentials, such as those from metadata services, to
	// construct clients.
	ClusterIssuerAmbientCredentials bool

	// IssuerAmbientCredentials controls whether an issuer should pick up ambient
	// credentials, such as those from metadata services, to construct clients.
	IssuerAmbientCredentials bool
}

type ACMEOptions struct {
	// ACMEHTTP01SolverImage is the image to use for solving ACME HTTP01
	// challenges
	HTTP01SolverImage string

	// HTTP01SolverResourceRequestCPU defines the ACME pod's resource request CPU size
	HTTP01SolverResourceRequestCPU resource.Quantity

	// HTTP01SolverResourceRequestMemory defines the ACME pod's resource request Memory size
	HTTP01SolverResourceRequestMemory resource.Quantity

	// HTTP01SolverResourceLimitsCPU defines the ACME pod's resource limits CPU size
	HTTP01SolverResourceLimitsCPU resource.Quantity

	// HTTP01SolverResourceLimitsMemory defines the ACME pod's resource limits Memory size
	HTTP01SolverResourceLimitsMemory resource.Quantity

	// ACMEHTTP01SolverRunAsNonRoot sets the ACME pod's ability to run as root
	ACMEHTTP01SolverRunAsNonRoot bool

	// HTTP01SolverNameservers is a list of nameservers to use when performing self-checks
	// for ACME HTTP01 validations.
	HTTP01SolverNameservers []string

	// DNS01CheckAuthoritative is a flag for controlling if auth nss are used
	// for checking propagation of an RR. This is the ideal scenario
	DNS01CheckAuthoritative bool

	// DNS01Nameservers is a list of nameservers to use when performing self-checks
	// for ACME DNS01 validations.
	DNS01Nameservers []string

	// AccountRegistry is used as a cache of ACME accounts between various
	// components of cert-manager
	AccountRegistry accounts.Registry

	// DNS01CheckRetryPeriod is the time the controller should wait between checking if a ACME dns entry exists.
	DNS01CheckRetryPeriod time.Duration
}

// IngressShimOptions contain default Issuer GVK config for the certificate-shim controllers.
// These are set from the cmd cli flags, allowing the controllers to support legacy annotations
// such as `kubernetes.io/tls-acme`.
type IngressShimOptions struct {
	DefaultIssuerName                 string
	DefaultIssuerKind                 string
	DefaultIssuerGroup                string
	DefaultAutoCertificateAnnotations []string
	ExtraCertificateAnnotations       []string
}

type CertificateOptions struct {
	// EnableOwnerRef controls whether the certificate is configured as an owner of
	// secret where the effective TLS certificate is stored.
	EnableOwnerRef bool
	// CopiedAnnotationPrefixes defines which annotations should be copied
	// Certificate -> CertificateRequest, CertificateRequest -> Order.
	CopiedAnnotationPrefixes []string
}

type SchedulerOptions struct {
	// MaxConcurrentChallenges determines the maximum number of challenges that can be
	// scheduled as 'processing' at once.
	MaxConcurrentChallenges int
}

// ContextFactory is used for constructing new Contexts whose clients have been
// configured with a User Agent built from the component name.
type ContextFactory struct {
	// baseRestConfig is the base Kubernetes REST config that can authenticate to
	// the Kubernetes API server.
	baseRestConfig *rest.Config

	// log is the factory logger which is used to construct event broadcasters.
	log logr.Logger

	// ctx is the base controller Context that all Contexts will be built from.
	ctx *Context
}

// NewContextFactory builds a ContextFactory that builds controller Contexts
// that have been configured for that components User Agent.
// All resulting Context's and clients contain the same RateLimiter and
// corresponding QPS and Burst buckets.
func NewContextFactory(ctx context.Context, opts ContextOptions) (*ContextFactory, error) {
	// Load the users Kubernetes config
	restConfig, err := kube.BuildClientConfig(opts.APIServerHost, opts.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("error creating rest config: %w", err)
	}
	restConfig = util.RestConfigWithUserAgent(restConfig)
	restConfig.QPS = opts.KubernetesAPIQPS
	restConfig.Burst = opts.KubernetesAPIBurst

	// Construct a single RateLimiter used across all built Context's clients. A
	// single rate limiter (with corresponding QPS and Burst buckets) are
	// preserved for all Contexts.
	// Adapted from
	// https://github.com/kubernetes/client-go/blob/v0.23.3/kubernetes/clientset.go#L431-L435
	if restConfig.RateLimiter == nil && restConfig.QPS > 0 {
		if restConfig.Burst <= 0 {
			return nil, errors.New("burst is required to be greater than 0 when RateLimiter is not set and QPS is set to greater than 0")
		}
		restConfig.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(restConfig.QPS, restConfig.Burst)
	}

	clients, err := buildClients(restConfig, opts)
	if err != nil {
		return nil, err
	}

	sharedInformerFactory := informers.NewSharedInformerFactoryWithOptions(clients.cmClient, resyncPeriod, informers.WithNamespace(opts.Namespace))

	var kubeSharedInformerFactory internalinformers.KubeInformerFactory
	if utilfeature.DefaultFeatureGate.Enabled(feature.SecretsFilteredCaching) {
		kubeSharedInformerFactory = internalinformers.NewFilteredSecretsKubeInformerFactory(ctx, clients.kubeClient, clients.metadataOnlyClient, resyncPeriod, opts.Namespace)
	} else {
		kubeSharedInformerFactory = internalinformers.NewBaseKubeInformerFactory(clients.kubeClient, resyncPeriod, opts.Namespace)
	}
	r, err := labels.NewRequirement(cmacme.DomainLabelKey, selection.Exists, nil)
	if err != nil {
		panic(fmt.Errorf("internal error: failed to build label selector to filter HTTP-01 challenge resources: %w", err))
	}
	isHTTP01ChallengeResourceLabelSelector := labels.NewSelector().Add(*r)
	http01ResourceMetadataInformerFactory := metadatainformer.NewFilteredSharedInformerFactory(clients.metadataOnlyClient, resyncPeriod, opts.Namespace, func(listOptions *metav1.ListOptions) {
		// metadataInformersFactory is at the moment only used for pods
		// and services for http-01 challenge which can be identified by
		// the same label keys, so it is okay to set the label selector
		// here. If we start using it for other resources then we'll
		// have to set the selectors on individual informers instead.
		listOptions.LabelSelector = isHTTP01ChallengeResourceLabelSelector.String()

	})

	gwSharedInformerFactory := gwinformers.NewSharedInformerFactoryWithOptions(clients.gwClient, resyncPeriod, gwinformers.WithNamespace(opts.Namespace))

	return &ContextFactory{
		baseRestConfig: restConfig,
		log:            logf.FromContext(ctx),
		ctx: &Context{
			RootContext:                            ctx,
			KubeSharedInformerFactory:              kubeSharedInformerFactory,
			SharedInformerFactory:                  sharedInformerFactory,
			GWShared:                               gwSharedInformerFactory,
			GatewaySolverEnabled:                   clients.gatewayAvailable,
			HTTP01ResourceMetadataInformersFactory: http01ResourceMetadataInformerFactory,
			ContextOptions:                         opts,
		},
	}, nil
}

// Build builds a new controller Context whose clients have a User Agent
// derived from the optional component name.
func (c *ContextFactory) Build(component ...string) (*Context, error) {
	restConfig := util.RestConfigWithUserAgent(c.baseRestConfig, component...)

	scheme := runtime.NewScheme()
	utilruntime.Must(kscheme.AddToScheme(scheme))
	utilruntime.Must(cmscheme.AddToScheme(scheme))
	utilruntime.Must(gwscheme.AddToScheme(scheme))

	clients, err := buildClients(restConfig, c.ctx.ContextOptions)
	if err != nil {
		return nil, err
	}

	// Create event broadcaster.
	// Add cert-manager types to the default Kubernetes Scheme so Events can be
	// logged properly.

	c.log.V(logf.DebugLevel).Info("creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(logf.WithInfof(c.log.V(logf.DebugLevel)).Infof)
	eventBroadcaster.StartRecordingToSink(&clientv1.EventSinkImpl{Interface: clients.kubeClient.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme, corev1.EventSource{Component: util.PrefixFromUserAgent(restConfig.UserAgent)})

	ctx := *c.ctx
	ctx.FieldManager = util.PrefixFromUserAgent(restConfig.UserAgent)
	ctx.RESTConfig = restConfig
	ctx.Scheme = scheme
	ctx.Client = clients.kubeClient
	ctx.CMClient = clients.cmClient
	ctx.GWClient = clients.gwClient
	ctx.MetadataClient = clients.metadataOnlyClient
	ctx.DiscoveryClient = clients.kubeClient.Discovery()
	ctx.Recorder = recorder

	return &ctx, nil
}

// contextClients is a helper struct containing API clients.
type contextClients struct {
	kubeClient         kubernetes.Interface
	cmClient           clientset.Interface
	gwClient           gwclient.Interface
	metadataOnlyClient metadata.Interface
	gatewayAvailable   bool
}

// buildClients builds all required clients for the context using the given
// REST config.
func buildClients(restConfig *rest.Config, opts ContextOptions) (contextClients, error) {
	httpClient, err := rest.HTTPClientFor(restConfig)
	if err != nil {
		return contextClients{}, fmt.Errorf("error creating HTTP client: %w", err)
	}

	// Create a cert-manager api client
	cmClient, err := clientset.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		return contextClients{}, fmt.Errorf("error creating cert-manager client: %w", err)
	}

	// Create a Kubernetes api client
	kubeClient, err := kubernetes.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		return contextClients{}, fmt.Errorf("error creating kubernetes client: %w", err)
	}

	// create a metadata-only client
	metadataOnlyClient, err := metadata.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		return contextClients{}, fmt.Errorf("error creating metadata-only client: %w", err)
	}

	var gatewayAvailable bool
	// Check if the Gateway API feature gate was enabled
	if utilfeature.DefaultFeatureGate.Enabled(feature.ExperimentalGatewayAPISupport) && opts.EnableGatewayAPI {
		// Check if the gateway API CRDs are available. If they are not found
		// return an error which will cause cert-manager to crashloopbackoff.
		d := kubeClient.Discovery()
		resources, err := d.ServerResourcesForGroupVersion(gwapi.GroupVersion.String())
		var GatewayAPINotAvailable = "the Gateway API CRDs do not seem to be present, but " + feature.ExperimentalGatewayAPISupport +
			" is set to true. Please install the gateway-api CRDs."
		switch {
		case apierrors.IsNotFound(err):
			return contextClients{}, fmt.Errorf("%s (%w)", GatewayAPINotAvailable, err)
		case err != nil:
			return contextClients{}, fmt.Errorf("while checking if the Gateway API CRD is installed: %w", err)
		case len(resources.APIResources) == 0:
			return contextClients{}, fmt.Errorf("%s (found %d APIResources in %s)", GatewayAPINotAvailable, len(resources.APIResources), gwapi.GroupVersion.String())
		default:
			gatewayAvailable = true
		}
	}

	// Create a GatewayAPI client.
	gwClient, err := gwclient.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		return contextClients{}, fmt.Errorf("error creating kubernetes client: %w", err)
	}

	return contextClients{kubeClient, cmClient, gwClient, metadataOnlyClient, gatewayAvailable}, nil
}
