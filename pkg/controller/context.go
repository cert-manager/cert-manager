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
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/discovery"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	gwclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gwinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"

	"github.com/jetstack/cert-manager/pkg/acme/accounts"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	informers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
	"github.com/jetstack/cert-manager/pkg/metrics"
)

// Context contains various types that are used by controller implementations.
// We purposely don't have specific informers/listers here, and instead keep
// a reference to a SharedInformerFactory so that controllers can choose
// themselves which listers are required.
type Context struct {
	// RootContext is the root context for the controller
	RootContext context.Context

	// StopCh is a channel that will be closed when the controller is signalled
	// to exit
	StopCh <-chan struct{}
	// RESTConfig is the loaded Kubernetes apiserver rest client configuration
	RESTConfig *rest.Config
	// Client is a Kubernetes clientset
	Client kubernetes.Interface
	// CMClient is a cert-manager clientset
	CMClient clientset.Interface
	// GWClient is a GatewayAPI clientset.
	GWClient gwclient.Interface
	// DiscoveryClient is a discovery interface. Usually set to Client.Discovery unless a fake client is in use.
	DiscoveryClient discovery.DiscoveryInterface

	// Recorder to record events to
	Recorder record.EventRecorder

	// KubeSharedInformerFactory can be used to obtain shared
	// SharedIndexInformer instances for Kubernetes types
	KubeSharedInformerFactory kubeinformers.SharedInformerFactory
	// SharedInformerFactory can be used to obtain shared SharedIndexInformer
	// instances
	SharedInformerFactory informers.SharedInformerFactory

	// The Gateway API is an external CRD, which means its shared informers are
	// not available in controllerpkg.Context.
	GWShared             gwinformers.SharedInformerFactory
	GatewaySolverEnabled bool

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
}

type IssuerOptions struct {
	// ClusterResourceNamespace is the namespace to store resources created by
	// non-namespaced resources (e.g. ClusterIssuer) in.
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
