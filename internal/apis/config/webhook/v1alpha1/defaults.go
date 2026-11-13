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

package v1alpha1

import (
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	logsapi "k8s.io/component-base/logs/api/v1"

	sharedv1alpha1 "github.com/cert-manager/cert-manager/pkg/apis/config/shared/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/apis/config/webhook/v1alpha1"
)

const (
	defaultPrometheusMetricsServerAddress = "0.0.0.0:9402"

	// defaultShutdownDelay is how long a terminating webhook Pod keeps
	// serving, so that it is removed from the Service's endpoints before it
	// stops listening. That took 0.3s to 0.4s in
	// https://github.com/cert-manager/cert-manager/issues/9590, and 5s stays
	// well inside the default terminationGracePeriodSeconds of 30s.
	defaultShutdownDelay = 5 * time.Second
)

var (
	// PEM size limits based on existing constants in internal/pem/decode.go
	defaultMaxCertificateSize int32 = 36500  // maxLeafCertificatePEMSize
	defaultMaxPrivateKeySize  int32 = 13000  // maxPrivateKeyPEMSize
	defaultMaxChainLength     int32 = 95000  // maxCertificateChainSize
	defaultMaxBundleSize      int32 = 330000 // maxBundleSize
)

func addDefaultingFuncs(scheme *runtime.Scheme) error {
	return RegisterDefaults(scheme)
}

func SetDefaults_WebhookConfiguration(obj *v1alpha1.WebhookConfiguration) {
	if obj.SecurePort == nil {
		obj.SecurePort = new(int32(6443))
	}
	if obj.HealthzPort == nil {
		obj.HealthzPort = new(int32(6080))
	}
	if obj.PprofAddress == "" {
		obj.PprofAddress = "localhost:6060"
	}

	if obj.MetricsListenAddress == "" {
		obj.MetricsListenAddress = defaultPrometheusMetricsServerAddress
	}

	// Only default a missing value, because an explicit 0 turns the delay off.
	if obj.ShutdownDelay == nil {
		obj.ShutdownDelay = sharedv1alpha1.DurationFromTime(defaultShutdownDelay)
	}

	logsapi.SetRecommendedLoggingConfiguration(&obj.Logging)
}

func SetDefaults_PEMSizeLimitsConfig(obj *v1alpha1.PEMSizeLimitsConfig) {
	if obj.MaxCertificateSize == nil {
		obj.MaxCertificateSize = &defaultMaxCertificateSize
	}

	if obj.MaxPrivateKeySize == nil {
		obj.MaxPrivateKeySize = &defaultMaxPrivateKeySize
	}

	if obj.MaxChainLength == nil {
		obj.MaxChainLength = &defaultMaxChainLength
	}

	if obj.MaxBundleSize == nil {
		obj.MaxBundleSize = &defaultMaxBundleSize
	}
}
