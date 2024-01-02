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

	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
)

func TestValidateControllerConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.ControllerConfiguration
		wantErr bool
	}{
		{
			"with valid config",
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
			},
			false,
		},
		{
			"with both filesystem and dynamic tls configured",
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				MetricsTLSConfig: config.TLSConfig{
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
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				MetricsTLSConfig: config.TLSConfig{
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
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				MetricsTLSConfig: config.TLSConfig{
					Filesystem: config.FilesystemServingConfig{
						CertFile: "/test.crt",
					},
				},
			},
			true,
		},
		{
			"with valid tls config missing certfile",
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				MetricsTLSConfig: config.TLSConfig{
					Filesystem: config.FilesystemServingConfig{
						KeyFile: "/test.key",
					},
				},
			},
			true,
		},
		{
			"with valid dynamic tls config",
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				MetricsTLSConfig: config.TLSConfig{
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
			&config.ControllerConfiguration{
				MetricsTLSConfig: config.TLSConfig{
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
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				MetricsTLSConfig: config.TLSConfig{
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
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				MetricsTLSConfig: config.TLSConfig{
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
			"with missing issuer kind",
			&config.ControllerConfiguration{
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
			},
			true,
		},
		{
			"with invalid kube-api-burst config",
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: -1, // Must be positive
				KubernetesAPIQPS:   1,
			},
			true,
		},
		{
			"with invalid kube-api-burst config",
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1, // Must be greater than KubernetesAPIQPS
				KubernetesAPIQPS:   2,
			},
			true,
		},
		{
			"with invalid kube-api-qps config",
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   -1, // Must be positive
			},
			true,
		},
		{
			"with valid acme http solver nameservers",
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				ACMEHTTP01Config: config.ACMEHTTP01Config{
					SolverNameservers: []string{
						"1.1.1.1:53",
						"8.8.8.8:53",
					},
				},
			},
			false,
		},
		{
			"with invalid acme http solver nameserver missing port",
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				ACMEHTTP01Config: config.ACMEHTTP01Config{
					SolverNameservers: []string{
						"1.1.1.1:53",
						"8.8.8.8",
					},
				},
			},
			true,
		},
		{
			"with valid acme dns recursive nameservers",
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				ACMEDNS01Config: config.ACMEDNS01Config{
					RecursiveNameservers: []string{
						"1.1.1.1:53",
						"https://example.com",
					},
				},
			},
			false,
		},
		{
			"with inalid acme dns recursive nameserver missing port",
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				ACMEDNS01Config: config.ACMEDNS01Config{
					RecursiveNameservers: []string{
						"1.1.1.1",
						"https://example.com",
					},
				},
			},
			true,
		},
		// TODO: Turns out url.ParseRequestURI allows a lot of bad URLs through,
		// including empty urls. We should replace that and uncomment this test.
		//
		// {
		// 	"with inalid acme dns recursive nameserver invalid url",
		// 	&config.ControllerConfiguration{
		// 		IngressShimConfig: config.IngressShimConfig{
		// 			DefaultIssuerKind: "Issuer",
		// 		},
		// 		KubernetesAPIBurst: 1,
		// 		KubernetesAPIQPS:   1,
		// 		ACMEDNS01Config: config.ACMEDNS01Config{
		// 			RecursiveNameservers: []string{
		// 				"1.1.1.1:53",
		// 				"https://",
		// 			},
		// 		},
		// 	},
		// 	true,
		// },
		{
			"with valid controllers named",
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				Controllers:        []string{"issuers", "clusterissuers"},
			},
			false,
		},
		{
			"with wildcard controllers named",
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				Controllers:        []string{"*"},
			},
			false,
		},
		{
			"with invalid controllers named",
			&config.ControllerConfiguration{
				IngressShimConfig: config.IngressShimConfig{
					DefaultIssuerKind: "Issuer",
				},
				KubernetesAPIBurst: 1,
				KubernetesAPIQPS:   1,
				Controllers:        []string{"foo"},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateControllerConfiguration(tt.config); (err != nil) != tt.wantErr {
				t.Errorf("ValidateControllerConfiguration() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
