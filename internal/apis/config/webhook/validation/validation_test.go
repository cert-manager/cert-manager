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

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/validation/field"
	logsapi "k8s.io/component-base/logs/api/v1"

	"github.com/cert-manager/cert-manager/internal/apis/config/shared"
	config "github.com/cert-manager/cert-manager/internal/apis/config/webhook"
)

func TestValidateWebhookConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		config *config.WebhookConfiguration
		errs   func(*config.WebhookConfiguration) field.ErrorList
	}{
		{
			"with no tls config",
			&config.WebhookConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
			},
			nil,
		},
		{
			"with invalid logging config",
			&config.WebhookConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "unknown",
				},
			},
			func(wc *config.WebhookConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("logging.format"), wc.Logging.Format, "Unsupported log format"),
				}
			},
		},
		{
			"with invalid tls config",
			&config.WebhookConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				TLSConfig: shared.TLSConfig{
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
			func(wc *config.WebhookConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("tlsConfig"), &wc.TLSConfig, "cannot specify both filesystem based and dynamic TLS configuration"),
				}
			},
		},
		{
			"with valid healthz port",
			&config.WebhookConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				HealthzPort: 8080,
			},
			nil,
		},
		{
			"with invalid healthz port",
			&config.WebhookConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				HealthzPort: 99999999,
			},
			func(wc *config.WebhookConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("healthzPort"), wc.HealthzPort, "must be a valid port number"),
				}
			},
		},
		{
			"with valid secure port",
			&config.WebhookConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				SecurePort: 8080,
			},
			nil,
		},
		{
			"with invalid secure port",
			&config.WebhookConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				SecurePort: 99999999,
			},
			func(wc *config.WebhookConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("securePort"), wc.SecurePort, "must be a valid port number"),
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errList := ValidateWebhookConfiguration(tt.config, nil)
			var expErrs field.ErrorList
			if tt.errs != nil {
				expErrs = tt.errs(tt.config)
			}
			assert.ElementsMatch(t, expErrs, errList)
		})
	}
}
