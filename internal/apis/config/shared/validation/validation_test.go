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

	"github.com/cert-manager/cert-manager/internal/apis/config/shared"
)

func TestValidateTLSConfig(t *testing.T) {
	tests := []struct {
		name   string
		config *shared.TLSConfig
		errs   func(*shared.TLSConfig) field.ErrorList
	}{
		{
			"with valid config",
			&shared.TLSConfig{},
			nil,
		},
		{
			"with both filesystem and dynamic tls configured",
			&shared.TLSConfig{
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
			func(cc *shared.TLSConfig) field.ErrorList {
				return field.ErrorList{
					field.Invalid(nil, cc, "cannot specify both filesystem based and dynamic TLS configuration"),
				}
			},
		},
		{
			"with valid filesystem tls config",
			&shared.TLSConfig{
				Filesystem: shared.FilesystemServingConfig{
					CertFile: "/test.crt",
					KeyFile:  "/test.key",
				},
			},
			nil,
		},
		{
			"with valid tls config missing keyfile",
			&shared.TLSConfig{
				Filesystem: shared.FilesystemServingConfig{
					CertFile: "/test.crt",
				},
			},
			func(cc *shared.TLSConfig) field.ErrorList {
				return field.ErrorList{
					field.Required(field.NewPath("filesystem.keyFile"), "must be specified when using filesystem based TLS config"),
				}
			},
		},
		{
			"with valid tls config missing certfile",
			&shared.TLSConfig{
				Filesystem: shared.FilesystemServingConfig{
					KeyFile: "/test.key",
				},
			},
			func(cc *shared.TLSConfig) field.ErrorList {
				return field.ErrorList{
					field.Required(field.NewPath("filesystem.certFile"), "must be specified when using filesystem based TLS config"),
				}
			},
		},
		{
			"with valid dynamic tls config",
			&shared.TLSConfig{
				Dynamic: shared.DynamicServingConfig{
					SecretNamespace: "cert-manager",
					SecretName:      "test",
					DNSNames:        []string{"example.com"},
				},
			},
			nil,
		},
		{
			"with dynamic tls missing secret namespace",
			&shared.TLSConfig{
				Dynamic: shared.DynamicServingConfig{
					SecretName: "test",
					DNSNames:   []string{"example.com"},
				},
			},
			func(cc *shared.TLSConfig) field.ErrorList {
				return field.ErrorList{
					field.Required(field.NewPath("dynamic.secretNamespace"), "must be specified when using dynamic TLS config"),
				}
			},
		},
		{
			"with dynamic tls missing secret name",
			&shared.TLSConfig{
				Dynamic: shared.DynamicServingConfig{
					SecretNamespace: "cert-manager",
					DNSNames:        []string{"example.com"},
				},
			},
			func(cc *shared.TLSConfig) field.ErrorList {
				return field.ErrorList{
					field.Required(field.NewPath("dynamic.secretName"), "must be specified when using dynamic TLS config"),
				}
			},
		},
		{
			"with dynamic tls missing dns names",
			&shared.TLSConfig{
				Dynamic: shared.DynamicServingConfig{
					SecretName:      "test",
					SecretNamespace: "cert-manager",
					DNSNames:        nil,
				},
			},
			func(cc *shared.TLSConfig) field.ErrorList {
				return field.ErrorList{
					field.Required(field.NewPath("dynamic.dnsNames"), "must be specified when using dynamic TLS config"),
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errList := ValidateTLSConfig(tt.config, nil)
			var expErrs field.ErrorList
			if tt.errs != nil {
				expErrs = tt.errs(tt.config)
			}
			assert.ElementsMatch(t, expErrs, errList)
		})
	}
}

func TestValidateLeaderElectionConfig(t *testing.T) {
	tests := []struct {
		name   string
		config *shared.LeaderElectionConfig
		errs   func(*shared.LeaderElectionConfig) field.ErrorList
	}{
		{
			"with valid config",
			&shared.LeaderElectionConfig{},
			nil,
		},
		{
			"with leader election enabled but missing durations",
			&shared.LeaderElectionConfig{
				Enabled: true,
			},
			func(cc *shared.LeaderElectionConfig) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("leaseDuration"), cc.LeaseDuration, "must be greater than 0"),
					field.Invalid(field.NewPath("renewDeadline"), cc.RenewDeadline, "must be greater than 0"),
					field.Invalid(field.NewPath("retryPeriod"), cc.RetryPeriod, "must be greater than 0"),
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errList := ValidateLeaderElectionConfig(tt.config, nil)
			var expErrs field.ErrorList
			if tt.errs != nil {
				expErrs = tt.errs(tt.config)
			}
			assert.ElementsMatch(t, expErrs, errList)
		})
	}
}
