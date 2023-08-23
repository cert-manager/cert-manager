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

package fuzzer

import (
	"time"

	fuzz "github.com/google/gofuzz"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"
	logsapi "k8s.io/component-base/logs/api/v1"

	"github.com/cert-manager/cert-manager/internal/apis/config/controller"
)

// Funcs returns the fuzzer functions for the controller config api group.
var Funcs = func(codecs runtimeserializer.CodecFactory) []interface{} {
	return []interface{}{
		// provide non-empty values for fields with defaults, so the defaulter doesn't change values during round-trip
		func(s *controller.ControllerConfiguration, c fuzz.Continue) {
			c.FuzzNoCustom(s) // fuzz self without calling this function again

			defaultTime := 60 * time.Second
			s.APIServerHost = "defaultHost"
			s.KubeConfig = "defaultConfig"
			s.KubernetesAPIQPS = 10
			s.KubernetesAPIBurst = 10
			s.ClusterResourceNamespace = "defaultClusterResourceNamespace"
			s.Namespace = "defaultNamespace"
			s.LeaderElectionConfig.Enabled = true
			s.LeaderElectionConfig.Namespace = "defaultLeaderElectionNamespace"
			s.LeaderElectionConfig.LeaseDuration = defaultTime
			s.LeaderElectionConfig.RenewDeadline = defaultTime
			s.LeaderElectionConfig.RetryPeriod = defaultTime
			s.Controllers = []string{"*"}
			s.ACMEHTTP01Config.SolverImage = "defaultACMEHTTP01SolverImage"
			s.ACMEHTTP01Config.SolverResourceRequestCPU = "10m"
			s.ACMEHTTP01Config.SolverResourceRequestMemory = "64Mi"
			s.ACMEHTTP01Config.SolverResourceLimitsCPU = "100m"
			s.ACMEHTTP01Config.SolverResourceLimitsMemory = "64Mi"
			s.ACMEHTTP01Config.SolverRunAsNonRoot = true
			s.ACMEHTTP01Config.SolverNameservers = []string{"8.8.8.8:53"}
			s.ClusterIssuerAmbientCredentials = true
			s.IssuerAmbientCredentials = true
			s.IngressShimConfig.DefaultIssuerName = "defaultTLSACMEIssuerName"
			s.IngressShimConfig.DefaultIssuerKind = "defaultIssuerKind"
			s.IngressShimConfig.DefaultIssuerGroup = "defaultTLSACMEIssuerGroup"
			s.IngressShimConfig.DefaultAutoCertificateAnnotations = []string{"kubernetes.io/tls-acme"}
			s.ACMEDNS01Config.RecursiveNameservers = []string{"8.8.8.8:53"}
			s.ACMEDNS01Config.RecursiveNameserversOnly = true
			s.EnableCertificateOwnerRef = true
			s.NumberOfConcurrentWorkers = 1
			s.MaxConcurrentChallenges = 1
			s.MetricsListenAddress = "0.0.0.0:9402"
			s.HealthzListenAddress = "0.0.0.0:9402"
			s.LeaderElectionConfig.HealthzTimeout = defaultTime
			s.EnablePprof = true
			s.PprofAddress = "something:1234"
			s.CopiedAnnotationPrefixes = []string{"*", "-kubectl.kubernetes.io/", "-fluxcd.io/", "-argocd.argoproj.io/"}

			logsapi.SetRecommendedLoggingConfiguration(&s.Logging)
		},
	}
}
