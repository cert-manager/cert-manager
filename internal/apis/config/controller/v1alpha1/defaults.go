/*
Copyright 2023 The cert-manager Authors.

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
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	logsapi "k8s.io/component-base/logs/api/v1"

	cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	"github.com/cert-manager/cert-manager/pkg/apis/config/controller/v1alpha1"
	sharedv1alpha1 "github.com/cert-manager/cert-manager/pkg/apis/config/shared/v1alpha1"
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
	"github.com/cert-manager/cert-manager/pkg/util"
)

var (
	defaultAPIServerHost              = ""
	defaultKubeconfig                 = ""
	defaultKubernetesAPIQPS   float32 = 20
	defaultKubernetesAPIBurst int32   = 50

	defaultClusterResourceNamespace = "kube-system"
	defaultNamespace                = ""

	defaultEnableProfiling = false
	defaultProfilerAddr    = "localhost:6060"

	defaultClusterIssuerAmbientCredentials = true
	defaultIssuerAmbientCredentials        = false

	defaultTLSACMEIssuerName         = ""
	defaultTLSACMEIssuerKind         = "Issuer"
	defaultTLSACMEIssuerGroup        = cm.GroupName
	defaultEnableCertificateOwnerRef = false
	defaultEnableGatewayAPI          = false

	defaultDNS01RecursiveNameserversOnly = false
	defaultDNS01RecursiveNameservers     = []string{}
	defaultDNS01CheckRetryPeriod         = 10 * time.Second

	defaultNumberOfConcurrentWorkers int32 = 5
	defaultMaxConcurrentChallenges   int32 = 60

	defaultPrometheusMetricsServerAddress = "0.0.0.0:9402"

	defaultHealthzServerAddress = "0.0.0.0:9403"
	// This default value is the same as used in Kubernetes controller-manager.
	// See:
	// https://github.com/kubernetes/kubernetes/blob/806b30170c61a38fedd54cc9ede4cd6275a1ad3b/cmd/kube-controller-manager/app/controllermanager.go#L202-L209
	defaultHealthzLeaderElectionTimeout = 20 * time.Second

	// default time period to wait between checking DNS01 and HTTP01 challenge propagation
	defaultACMEHTTP01SolverImage                 = fmt.Sprintf("quay.io/jetstack/cert-manager-acmesolver:%s", util.AppVersion)
	defaultACMEHTTP01SolverResourceRequestCPU    = "10m"
	defaultACMEHTTP01SolverResourceRequestMemory = "64Mi"
	defaultACMEHTTP01SolverResourceLimitsCPU     = "100m"
	defaultACMEHTTP01SolverResourceLimitsMemory  = "64Mi"
	defaultACMEHTTP01SolverRunAsNonRoot          = true
	defaultACMEHTTP01SolverNameservers           = []string{}

	defaultAutoCertificateAnnotations  = []string{"kubernetes.io/tls-acme"}
	defaultExtraCertificateAnnotations = []string{}

	AllControllers = []string{
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
		// experimental CSR controllers
		csracmecontroller.CSRControllerName,
		csrcacontroller.CSRControllerName,
		csrselfsignedcontroller.CSRControllerName,
		csrvenaficontroller.CSRControllerName,
		csrvaultcontroller.CSRControllerName,
	}

	DefaultEnabledControllers = []string{
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

	ExperimentalCertificateSigningRequestControllers = []string{
		csracmecontroller.CSRControllerName,
		csrcacontroller.CSRControllerName,
		csrselfsignedcontroller.CSRControllerName,
		csrvenaficontroller.CSRControllerName,
		csrvaultcontroller.CSRControllerName,
	}

	ClusterScopedControllers = []string{
		clusterissuerscontroller.ControllerName,
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

func addDefaultingFuncs(scheme *runtime.Scheme) error {
	return RegisterDefaults(scheme)
}

func SetDefaults_ControllerConfiguration(obj *v1alpha1.ControllerConfiguration) {
	if obj.APIServerHost == "" {
		obj.APIServerHost = defaultAPIServerHost
	}

	if obj.KubeConfig == "" {
		obj.KubeConfig = defaultKubeconfig
	}

	if obj.KubernetesAPIQPS == nil {
		obj.KubernetesAPIQPS = &defaultKubernetesAPIQPS
	}

	if obj.KubernetesAPIBurst == nil {
		obj.KubernetesAPIBurst = &defaultKubernetesAPIBurst
	}

	if obj.Namespace == "" {
		obj.Namespace = defaultNamespace
	}

	if obj.ClusterResourceNamespace == "" {
		obj.ClusterResourceNamespace = defaultClusterResourceNamespace
	}

	if len(obj.Controllers) == 0 {
		obj.Controllers = []string{"*"}
	}

	if obj.IssuerAmbientCredentials == nil {
		obj.IssuerAmbientCredentials = &defaultIssuerAmbientCredentials
	}

	if obj.ClusterIssuerAmbientCredentials == nil {
		obj.ClusterIssuerAmbientCredentials = &defaultClusterIssuerAmbientCredentials
	}

	if obj.EnableCertificateOwnerRef == nil {
		obj.EnableCertificateOwnerRef = &defaultEnableCertificateOwnerRef
	}

	if obj.EnableGatewayAPI == nil {
		obj.EnableGatewayAPI = &defaultEnableGatewayAPI
	}

	if len(obj.CopiedAnnotationPrefixes) == 0 {
		obj.CopiedAnnotationPrefixes = defaultCopiedAnnotationPrefixes
	}

	if obj.NumberOfConcurrentWorkers == nil {
		obj.NumberOfConcurrentWorkers = &defaultNumberOfConcurrentWorkers
	}

	if obj.MaxConcurrentChallenges == nil {
		obj.MaxConcurrentChallenges = &defaultMaxConcurrentChallenges
	}

	if obj.MetricsListenAddress == "" {
		obj.MetricsListenAddress = defaultPrometheusMetricsServerAddress
	}

	if obj.HealthzListenAddress == "" {
		obj.HealthzListenAddress = defaultHealthzServerAddress
	}

	if obj.EnablePprof == nil {
		obj.EnablePprof = &defaultEnableProfiling
	}

	if obj.PprofAddress == "" {
		obj.PprofAddress = defaultProfilerAddr
	}

	logsapi.SetRecommendedLoggingConfiguration(&obj.Logging)
}

func SetDefaults_LeaderElectionConfig(obj *v1alpha1.LeaderElectionConfig) {
	if obj.HealthzTimeout.IsZero() {
		obj.HealthzTimeout = sharedv1alpha1.DurationFromTime(defaultHealthzLeaderElectionTimeout)
	}
}

func SetDefaults_IngressShimConfig(obj *v1alpha1.IngressShimConfig) {
	if obj.DefaultIssuerName == "" {
		obj.DefaultIssuerName = defaultTLSACMEIssuerName
	}

	if obj.DefaultIssuerKind == "" {
		obj.DefaultIssuerKind = defaultTLSACMEIssuerKind
	}

	if obj.DefaultIssuerGroup == "" {
		obj.DefaultIssuerGroup = defaultTLSACMEIssuerGroup
	}

	if len(obj.DefaultAutoCertificateAnnotations) == 0 {
		obj.DefaultAutoCertificateAnnotations = defaultAutoCertificateAnnotations
	}

	if len(obj.ExtraCertificateAnnotations) == 0 {
		obj.ExtraCertificateAnnotations = defaultExtraCertificateAnnotations
	}
}

func SetDefaults_ACMEHTTP01Config(obj *v1alpha1.ACMEHTTP01Config) {
	if obj.SolverImage == "" {
		obj.SolverImage = defaultACMEHTTP01SolverImage
	}

	if obj.SolverResourceRequestCPU == "" {
		obj.SolverResourceRequestCPU = defaultACMEHTTP01SolverResourceRequestCPU
	}

	if obj.SolverResourceRequestMemory == "" {
		obj.SolverResourceRequestMemory = defaultACMEHTTP01SolverResourceRequestMemory
	}

	if obj.SolverResourceLimitsCPU == "" {
		obj.SolverResourceLimitsCPU = defaultACMEHTTP01SolverResourceLimitsCPU
	}

	if obj.SolverResourceLimitsMemory == "" {
		obj.SolverResourceLimitsMemory = defaultACMEHTTP01SolverResourceLimitsMemory
	}

	if obj.SolverRunAsNonRoot == nil {
		obj.SolverRunAsNonRoot = &defaultACMEHTTP01SolverRunAsNonRoot
	}

	if len(obj.SolverNameservers) == 0 {
		obj.SolverNameservers = defaultACMEHTTP01SolverNameservers
	}
}

func SetDefaults_ACMEDNS01Config(obj *v1alpha1.ACMEDNS01Config) {
	if len(obj.RecursiveNameservers) == 0 {
		obj.RecursiveNameservers = defaultDNS01RecursiveNameservers
	}

	if obj.RecursiveNameserversOnly == nil {
		obj.RecursiveNameserversOnly = &defaultDNS01RecursiveNameserversOnly
	}

	if obj.CheckRetryPeriod.IsZero() {
		obj.CheckRetryPeriod = sharedv1alpha1.DurationFromTime(defaultDNS01CheckRetryPeriod)
	}
}
