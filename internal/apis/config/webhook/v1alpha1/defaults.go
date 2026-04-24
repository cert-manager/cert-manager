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
	"k8s.io/apimachinery/pkg/runtime"
	logsapi "k8s.io/component-base/logs/api/v1"
	"k8s.io/utils/ptr"

	"github.com/cert-manager/cert-manager/pkg/apis/config/webhook/v1alpha1"
)

const defaultPrometheusMetricsServerAddress = "0.0.0.0:9402"

// PEM size limits based on existing constants in internal/pem/decode.go
var (
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
		obj.SecurePort = ptr.To(int32(6443))
	}
	if obj.HealthzPort == nil {
		obj.HealthzPort = ptr.To(int32(6080))
	}
	if obj.PprofAddress == "" {
		obj.PprofAddress = "localhost:6060"
	}

	if obj.MetricsListenAddress == "" {
		obj.MetricsListenAddress = defaultPrometheusMetricsServerAddress
	}

	logsapi.SetRecommendedLoggingConfiguration(&obj.Logging)
}

// SetDefaults_PEMSizeLimitsConfig sets default values for PEM size limits configuration.
// These limits control the maximum sizes for PEM-encoded certificates and keys.
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
