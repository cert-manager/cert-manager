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

			if s.ClusterResourceNamespace == "" {
				s.ClusterResourceNamespace = "test-roundtrip"
			}

			if len(s.Controllers) == 0 {
				s.Controllers = []string{"test-roundtrip"}
			}

			if len(s.CopiedAnnotationPrefixes) == 0 {
				s.CopiedAnnotationPrefixes = []string{"test-roundtrip"}
			}

			if s.MetricsListenAddress == "" {
				s.MetricsListenAddress = "test-roundtrip"
			}

			if s.HealthzListenAddress == "" {
				s.HealthzListenAddress = "test-roundtrip"
			}

			if s.PprofAddress == "" {
				s.PprofAddress = "test-roundtrip"
			}

			logsapi.SetRecommendedLoggingConfiguration(&s.Logging)

			if s.LeaderElectionConfig.Namespace == "" {
				s.LeaderElectionConfig.Namespace = "test-roundtrip"
			}

			if s.LeaderElectionConfig.LeaseDuration == time.Duration(0) {
				s.LeaderElectionConfig.LeaseDuration = time.Second * 8875
			}

			if s.LeaderElectionConfig.RenewDeadline == time.Duration(0) {
				s.LeaderElectionConfig.RenewDeadline = time.Second * 8875
			}

			if s.LeaderElectionConfig.RetryPeriod == time.Duration(0) {
				s.LeaderElectionConfig.RetryPeriod = time.Second * 8875
			}

			if s.LeaderElectionConfig.HealthzTimeout == time.Duration(0) {
				s.LeaderElectionConfig.HealthzTimeout = time.Second * 8875
			}

			if s.IngressShimConfig.DefaultIssuerKind == "" {
				s.IngressShimConfig.DefaultIssuerKind = "test-roundtrip"
			}

			if s.IngressShimConfig.DefaultIssuerGroup == "" {
				s.IngressShimConfig.DefaultIssuerGroup = "test-roundtrip"
			}

			if len(s.IngressShimConfig.DefaultAutoCertificateAnnotations) == 0 {
				s.IngressShimConfig.DefaultAutoCertificateAnnotations = []string{"test-roundtrip"}
			}

			if s.ACMEHTTP01Config.SolverImage == "" {
				s.ACMEHTTP01Config.SolverImage = "test-roundtrip"
			}

			if s.ACMEHTTP01Config.SolverResourceRequestCPU == "" {
				s.ACMEHTTP01Config.SolverResourceRequestCPU = "test-roundtrip"
			}

			if s.ACMEHTTP01Config.SolverResourceRequestMemory == "" {
				s.ACMEHTTP01Config.SolverResourceRequestMemory = "test-roundtrip"
			}

			if s.ACMEHTTP01Config.SolverResourceLimitsCPU == "" {
				s.ACMEHTTP01Config.SolverResourceLimitsCPU = "test-roundtrip"
			}

			if s.ACMEHTTP01Config.SolverResourceLimitsMemory == "" {
				s.ACMEHTTP01Config.SolverResourceLimitsMemory = "test-roundtrip"
			}

			if s.ACMEDNS01Config.CheckRetryPeriod == time.Duration(0) {
				s.ACMEDNS01Config.CheckRetryPeriod = time.Second * 8875
			}
		},
	}
}
