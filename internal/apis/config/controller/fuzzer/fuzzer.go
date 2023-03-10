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
	fuzz "github.com/google/gofuzz"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/component-base/logs"
	"k8s.io/utils/pointer"

	"time"

	"github.com/cert-manager/cert-manager/internal/apis/config/controller"
)

// Funcs returns the fuzzer functions for the controller config api group.
var Funcs = func(codecs runtimeserializer.CodecFactory) []interface{} {
	return []interface{}{
		func(s *controller.ControllerConfiguration, c fuzz.Continue) {
			c.FuzzNoCustom(s) // fuzz self without calling this function again

			defaultTime := 60 * time.Second
			if s.APIServerHost == "" {
				s.APIServerHost = "defaultHost"
			}
			if s.KubeConfig == "" {
				s.KubeConfig = "defaultConfig"
			}
			if s.KubernetesAPIQPS == nil {
				s.KubernetesAPIQPS = pointer.Float32(10)
			}
			if s.KubernetesAPIBurst == nil {
				s.KubernetesAPIBurst = pointer.Int(10)
			}
			if s.ClusterResourceNamespace == "" {
				s.ClusterResourceNamespace = "defaultClusterResourceNamespace"
			}
			if s.Namespace == "" {
				s.Namespace = "defaultNamespace"
			}
			if s.LeaderElect == nil {
				s.LeaderElect = pointer.Bool(true)
			}
			if s.LeaderElectionNamespace == "" {
				s.LeaderElectionNamespace = "defaultLeaderElectionNamespace"
			}
			if s.LeaderElectionLeaseDuration == time.Duration(0) {
				s.LeaderElectionLeaseDuration = defaultTime
			}
			if s.LeaderElectionRenewDeadline == time.Duration(0) {
				s.LeaderElectionRenewDeadline = defaultTime
			}
			if s.LeaderElectionRetryPeriod == time.Duration(0) {
				s.LeaderElectionRetryPeriod = defaultTime
			}
			if len(s.Controllers) == 0 {
				s.Controllers = []string{"*"}
			}
			if s.ACMEHTTP01SolverImage == "" {
				s.ACMEHTTP01SolverImage = "defaultACMEHTTP01SolverImage"
			}
			if s.ACMEHTTP01SolverResourceRequestCPU == "" {
				s.ACMEHTTP01SolverResourceRequestCPU = "10m"
			}
			if s.ACMEHTTP01SolverResourceRequestMemory == "" {
				s.ACMEHTTP01SolverResourceRequestMemory = "64Mi"
			}
			if s.ACMEHTTP01SolverResourceLimitsCPU == "" {
				s.ACMEHTTP01SolverResourceLimitsCPU = "100m"
			}
			if s.ACMEHTTP01SolverResourceLimitsMemory == "" {
				s.ACMEHTTP01SolverResourceLimitsMemory = "64Mi"
			}
			if s.ACMEHTTP01SolverRunAsNonRoot == nil {
				s.ACMEHTTP01SolverRunAsNonRoot = pointer.Bool(true)
			}
			if len(s.ACMEHTTP01SolverNameservers) == 0 {
				s.ACMEHTTP01SolverNameservers = []string{"8.8.8.8:53"}
			}
			if s.ClusterIssuerAmbientCredentials == nil {
				s.ClusterIssuerAmbientCredentials = pointer.Bool(true)
			}
			if s.IssuerAmbientCredentials == nil {
				s.IssuerAmbientCredentials = pointer.Bool(true)
			}
			if s.DefaultIssuerName == "" {
				s.DefaultIssuerName = "defaultTLSACMEIssuerName"
			}
			if s.DefaultIssuerKind == "" {
				s.DefaultIssuerKind = "defaultIssuerKind"
			}
			if s.DefaultIssuerGroup == "" {
				s.DefaultIssuerGroup = "defaultTLSACMEIssuerGroup"
			}
			if len(s.DefaultAutoCertificateAnnotations) == 0 {
				s.DefaultAutoCertificateAnnotations = []string{"kubernetes.io/tls-acme"}
			}
			if len(s.DNS01RecursiveNameservers) == 0 {
				s.DNS01RecursiveNameservers = []string{"8.8.8.8:53"}
			}
			if s.EnableCertificateOwnerRef == nil {
				s.EnableCertificateOwnerRef = pointer.Bool(true)
			}
			if s.DNS01RecursiveNameserversOnly == nil {
				s.DNS01RecursiveNameserversOnly = pointer.Bool(true)
			}
			if s.NumberOfConcurrentWorkers == nil {
				s.NumberOfConcurrentWorkers = pointer.Int(1)
			}
			if s.MaxConcurrentChallenges == nil {
				s.MaxConcurrentChallenges = pointer.Int(1)
			}
			if s.MetricsListenAddress == "" {
				s.MetricsListenAddress = "0.0.0.0:9402"
			}
			if s.HealthzListenAddress == "" {
				s.HealthzListenAddress = "0.0.0.0:9402"
			}
			if s.HealthzLeaderElectionTimeout == time.Duration(0) {
				s.HealthzLeaderElectionTimeout = defaultTime
			}
			if s.EnablePprof == nil {
				s.EnablePprof = pointer.Bool(true)
			}
			if s.PprofAddress == "" {
				s.PprofAddress = "something:1234"
			}
			if s.Logging == nil {
				s.Logging = logs.NewOptions()
			}

			if len(s.CopiedAnnotationPrefixes) == 0 {
				s.CopiedAnnotationPrefixes = []string{"*", "-kubectl.kubernetes.io/", "-fluxcd.io/", "-argocd.argoproj.io/"}
			}

		},
	}
}
