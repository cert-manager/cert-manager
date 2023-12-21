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

	config "github.com/cert-manager/cert-manager/internal/apis/config/webhook"
)

func TestValidateWebhookConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.WebhookConfiguration
		wantErr bool
	}{
		{
			"with no tls config",
			&config.WebhookConfiguration{},
			false,
		},
		{
			"with both filesystem and dynamic tls configured",
			&config.WebhookConfiguration{
				TLSConfig: config.TLSConfig{
					Filesystem: config.FilesystemServingConfig{
						CertFile: "/test.crt",
						KeyFile:  "/test.key",
					},
					Dynamic: config.DynamicServingConfig{
						SecretNamespace: "cert-manager",
						SecretName:      "test",
						DNSNames:        []string{"example.com"},
					},
				},
			},
			true,
		},
		{
			"with valid filesystem tls config",
			&config.WebhookConfiguration{
				TLSConfig: config.TLSConfig{
					Filesystem: config.FilesystemServingConfig{
						CertFile: "/test.crt",
						KeyFile:  "/test.key",
					},
				},
			},
			false,
		},
		{
			"with valid tls config missing keyfile",
			&config.WebhookConfiguration{
				TLSConfig: config.TLSConfig{
					Filesystem: config.FilesystemServingConfig{
						CertFile: "/test.crt",
					},
				},
			},
			true,
		},
		{
			"with valid tls config missing certfile",
			&config.WebhookConfiguration{
				TLSConfig: config.TLSConfig{
					Filesystem: config.FilesystemServingConfig{
						KeyFile: "/test.key",
					},
				},
			},
			true,
		},
		{
			"with valid dynamic tls config",
			&config.WebhookConfiguration{
				TLSConfig: config.TLSConfig{
					Dynamic: config.DynamicServingConfig{
						SecretNamespace: "cert-manager",
						SecretName:      "test",
						DNSNames:        []string{"example.com"},
					},
				},
			},
			false,
		},
		{
			"with dynamic tls missing secret namespace",
			&config.WebhookConfiguration{
				TLSConfig: config.TLSConfig{
					Dynamic: config.DynamicServingConfig{
						SecretName: "test",
						DNSNames:   []string{"example.com"},
					},
				},
			},
			true,
		},
		{
			"with dynamic tls missing secret name",
			&config.WebhookConfiguration{
				TLSConfig: config.TLSConfig{
					Dynamic: config.DynamicServingConfig{
						SecretNamespace: "cert-manager",
						DNSNames:        []string{"example.com"},
					},
				},
			},
			true,
		},
		{
			"with dynamic tls missing dns names",
			&config.WebhookConfiguration{
				TLSConfig: config.TLSConfig{
					Dynamic: config.DynamicServingConfig{
						SecretName:      "test",
						SecretNamespace: "cert-manager",
						DNSNames:        nil,
					},
				},
			},
			true,
		},
		{
			"with valid healthz port",
			&config.WebhookConfiguration{
				HealthzPort: 8080,
			},
			false,
		},
		{
			"with invalid healthz port",
			&config.WebhookConfiguration{
				HealthzPort: 99999999,
			},
			true,
		},

		{
			"with valid secure port",
			&config.WebhookConfiguration{
				SecurePort: 8080,
			},
			false,
		},
		{
			"with invalid secure port",
			&config.WebhookConfiguration{
				SecurePort: 99999999,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateWebhookConfiguration(tt.config); (err != nil) != tt.wantErr {
				t.Errorf("ValidateWebhookConfiguration() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
