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

package validation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/validation/field"
	logsapi "k8s.io/component-base/logs/api/v1"

	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
	"github.com/cert-manager/cert-manager/internal/apis/config/shared"
)

// validPEMSizeLimitsConfig returns a valid PEMSizeLimitsConfig for testing
func validPEMSizeLimitsConfig() config.PEMSizeLimitsConfig {
	return config.PEMSizeLimitsConfig{
		MaxCertificateSize: 6500,
		MaxPrivateKeySize:  13000,
		MaxChainLength:     10,
		MaxBundleSize:      330000,
	}
}

func TestValidateControllerConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		config *config.ControllerConfiguration
		errs   func(*config.ControllerConfiguration) field.ErrorList
	}{
		{
			"with valid config",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst:  1,
				KubernetesAPIQPS:    1,
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
			},
			nil,
		},
		{
			"with invalid logging config",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "unknown",
				},
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst:  1,
				KubernetesAPIQPS:    1,
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
			},
			func(wc *config.ControllerConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("logging.format"), wc.Logging.Format, "Unsupported log format"),
				}
			},
		},
		{
			"with invalid leader election healthz timeout",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				LeaderElectionConfig: config.LeaderElectionConfig{
					LeaderElectionConfig: shared.LeaderElectionConfig{
						Enabled:       true,
						LeaseDuration: time.Second,
						RenewDeadline: time.Second,
						RetryPeriod:   time.Second,
					},
					HealthzTimeout: 0,
				},
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst:  1,
				KubernetesAPIQPS:    1,
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
			},
			func(cc *config.ControllerConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("leaderElectionConfig.healthzTimeout"), cc.LeaderElectionConfig.HealthzTimeout, "must be greater than 0"),
				}
			},
		},
		{
			"with invalid leader election config",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				LeaderElectionConfig: config.LeaderElectionConfig{
					LeaderElectionConfig: shared.LeaderElectionConfig{
						Enabled: true,
					},
				},
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst:  1,
				KubernetesAPIQPS:    1,
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
			},
			func(cc *config.ControllerConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("leaderElectionConfig.healthzTimeout"), cc.LeaderElectionConfig.HealthzTimeout, "must be greater than 0"),
					field.Invalid(field.NewPath("leaderElectionConfig.leaseDuration"), cc.LeaderElectionConfig.LeaseDuration, "must be greater than 0"),
					field.Invalid(field.NewPath("leaderElectionConfig.renewDeadline"), cc.LeaderElectionConfig.RenewDeadline, "must be greater than 0"),
					field.Invalid(field.NewPath("leaderElectionConfig.retryPeriod"), cc.LeaderElectionConfig.RetryPeriod, "must be greater than 0"),
				}
			},
		},
		{
			"with invalid metrics tls config",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
				MetricsTLSConfig: shared.TLSConfig{
					Filesystem: shared.FilesystemServingConfig{
						CertFile: "/test.crt",
						KeyFile:  "/test.key",
					},
					Dynamic: shared.DynamicServingConfig{
						SecretNamespace: "cert-manager",
						SecretName:      "test",
						DNSNames:        []string{"example.com"},
					},
				},
			},
			func(cc *config.ControllerConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("metricsTLSConfig"), &cc.MetricsTLSConfig, "cannot specify both filesystem based and dynamic TLS configuration"),
				}
			},
		},
		{
			"with missing issuer kind",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				KubernetesAPIBurst:  1,
				KubernetesAPIQPS:    1,
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
			},
			func(cc *config.ControllerConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Required(field.NewPath("ingressShimConfig.defaultIssuerKind"), "must not be empty"),
				}
			},
		},
		{
			"with invalid kube-api-burst config",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst:  -1, // Must be positive
				KubernetesAPIQPS:    1,
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
			},
			func(cc *config.ControllerConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("kubernetesAPIBurst"), cc.KubernetesAPIBurst, "must be greater than 0"),
					field.Invalid(field.NewPath("kubernetesAPIBurst"), cc.KubernetesAPIBurst, "must be higher or equal to kubernetesAPIQPS"),
				}
			},
		},
		{
			"with invalid kube-api-burst config",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst:  1, // Must be greater than KubernetesAPIQPS
				KubernetesAPIQPS:    2,
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
			},
			func(cc *config.ControllerConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("kubernetesAPIBurst"), cc.KubernetesAPIBurst, "must be higher or equal to kubernetesAPIQPS"),
				}
			},
		},
		{
			"with invalid kube-api-qps config",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst:  1,
				KubernetesAPIQPS:    -1, // Must be positive
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
			},
			func(cc *config.ControllerConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("kubernetesAPIQPS"), cc.KubernetesAPIQPS, "must be greater than 0"),
				}
			},
		},
		{
			"with valid acme http solver nameservers",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
				ACMEHTTP01Config: config.ACMEHTTP01Config{
					SolverNameservers: []string{
						"1.1.1.1:53",
						"8.8.8.8:53",
					},
				},
			},
			nil,
		},
		{
			"with invalid acme http solver nameserver missing port",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
				ACMEHTTP01Config: config.ACMEHTTP01Config{
					SolverNameservers: []string{
						"1.1.1.1:53",
						"8.8.8.8",
					},
				},
			},
			func(cc *config.ControllerConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("acmeHTTP01Config.solverNameservers[1]"), cc.ACMEHTTP01Config.SolverNameservers[1], "must be in the format <ip address>:<port>"),
				}
			},
		},
		{
			"with valid acme dns recursive nameservers",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
				ACMEDNS01Config: config.ACMEDNS01Config{
					RecursiveNameservers: []string{
						"1.1.1.1:53",
						"https://example.com",
					},
				},
			},
			nil,
		},
		{
			"with invalid acme dns recursive nameserver missing port",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
				ACMEDNS01Config: config.ACMEDNS01Config{
					RecursiveNameservers: []string{
						"1.1.1.1",
						"https://example.com",
					},
				},
			},
			func(cc *config.ControllerConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("acmeDNS01Config.recursiveNameservers[0]"), cc.ACMEDNS01Config.RecursiveNameservers[0], "must be in the format <ip address>:<port>"),
				}
			},
		},
		{
			"with invalid acme dns recursive nameserver invalid url",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
				ACMEDNS01Config: config.ACMEDNS01Config{
					RecursiveNameservers: []string{
						"1.1.1.1:53",
						"https://",
					},
				},
			},
			func(cc *config.ControllerConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("acmeDNS01Config.recursiveNameservers[1]"), cc.ACMEDNS01Config.RecursiveNameservers[1], "must be in the format https://<DoH RFC 8484 server address>"),
				}
			},
		},
		{
			"with valid controllers named",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
				Controllers:        []string{"issuers", "clusterissuers"},
			},
			nil,
		},
		{
			"with wildcard controllers named",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
				Controllers:        []string{"*"},
			},
			nil,
		},
		{
			"with invalid controllers named",
			&config.ControllerConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				PEMSizeLimitsConfig: validPEMSizeLimitsConfig(),
				Controllers:        []string{"foo"},
			},
			func(cc *config.ControllerConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("controllers").Index(0), "foo", "is not in the list of known controllers"),
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errList := ValidateControllerConfiguration(tt.config, nil)
			var expErrs field.ErrorList
			if tt.errs != nil {
				expErrs = tt.errs(tt.config)
			}
			assert.ElementsMatch(t, expErrs, errList)
		})
	}
}

func TestValidatePEMSizeLimitsConfig(t *testing.T) {
	tests := []struct {
		name   string
		config *config.PEMSizeLimitsConfig
		errs   field.ErrorList
	}{
		{
			"with valid PEM size limits config",
			&config.PEMSizeLimitsConfig{
				MaxCertificateSize: 6500,
				MaxPrivateKeySize:  13000,
				MaxChainLength:     10,
				MaxBundleSize:      330000,
			},
			nil,
		},
		{
			"with zero MaxCertificateSize",
			&config.PEMSizeLimitsConfig{
				MaxCertificateSize: 0,
				MaxPrivateKeySize:  13000,
				MaxChainLength:     10,
				MaxBundleSize:      330000,
			},
			field.ErrorList{
				field.Invalid(field.NewPath("").Child("maxCertificateSize"), 0, "must be greater than 0"),
			},
		},
		{
			"with zero MaxPrivateKeySize",
			&config.PEMSizeLimitsConfig{
				MaxCertificateSize: 6500,
				MaxPrivateKeySize:  0,
				MaxChainLength:     10,
				MaxBundleSize:      330000,
			},
			field.ErrorList{
				field.Invalid(field.NewPath("").Child("maxPrivateKeySize"), 0, "must be greater than 0"),
			},
		},
		{
			"with zero MaxChainLength",
			&config.PEMSizeLimitsConfig{
				MaxCertificateSize: 6500,
				MaxPrivateKeySize:  13000,
				MaxChainLength:     0,
				MaxBundleSize:      330000,
			},
			field.ErrorList{
				field.Invalid(field.NewPath("").Child("maxChainLength"), 0, "must be greater than 0"),
			},
		},
		{
			"with zero MaxBundleSize",
			&config.PEMSizeLimitsConfig{
				MaxCertificateSize: 6500,
				MaxPrivateKeySize:  13000,
				MaxChainLength:     10,
				MaxBundleSize:      0,
			},
			field.ErrorList{
				field.Invalid(field.NewPath("").Child("maxBundleSize"), 0, "must be greater than 0"),
				field.Invalid(field.NewPath("").Child("maxCertificateSize"), 6500, "must not be larger than maxBundleSize"),
				field.Invalid(field.NewPath("").Child("maxChainLength"), 10, "maxChainLength * maxCertificateSize must not exceed maxBundleSize"),
			},
		},
		{
			"with MaxCertificateSize larger than MaxBundleSize",
			&config.PEMSizeLimitsConfig{
				MaxCertificateSize: 400000,
				MaxPrivateKeySize:  13000,
				MaxChainLength:     10,
				MaxBundleSize:      330000,
			},
			field.ErrorList{
				field.Invalid(field.NewPath("").Child("maxCertificateSize"), 400000, "must not be larger than maxBundleSize"),
				field.Invalid(field.NewPath("").Child("maxChainLength"), 10, "maxChainLength * maxCertificateSize must not exceed maxBundleSize"),
			},
		},
		{
			"with chain size exceeding bundle size",
			&config.PEMSizeLimitsConfig{
				MaxCertificateSize: 50000,
				MaxPrivateKeySize:  13000,
				MaxChainLength:     10,
				MaxBundleSize:      330000,
			},
			field.ErrorList{
				field.Invalid(field.NewPath("").Child("maxChainLength"), 10, "maxChainLength * maxCertificateSize must not exceed maxBundleSize"),
			},
		},
		{
			"with all zero values",
			&config.PEMSizeLimitsConfig{
				MaxCertificateSize: 0,
				MaxPrivateKeySize:  0,
				MaxChainLength:     0,
				MaxBundleSize:      0,
			},
			field.ErrorList{
				field.Invalid(field.NewPath("").Child("maxCertificateSize"), 0, "must be greater than 0"),
				field.Invalid(field.NewPath("").Child("maxPrivateKeySize"), 0, "must be greater than 0"),
				field.Invalid(field.NewPath("").Child("maxChainLength"), 0, "must be greater than 0"),
				field.Invalid(field.NewPath("").Child("maxBundleSize"), 0, "must be greater than 0"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			errs := validatePEMSizeLimitsConfig(test.config, field.NewPath(""))
			assert.ElementsMatch(t, test.errs, errs)
		})
	}
}
