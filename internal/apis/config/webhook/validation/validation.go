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
	"fmt"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	config "github.com/cert-manager/cert-manager/internal/apis/config/webhook"
)

func ValidateWebhookConfiguration(cfg *config.WebhookConfiguration) error {
	var allErrors []error
	if cfg.TLSConfig.FilesystemConfigProvided() && cfg.TLSConfig.DynamicConfigProvided() {
		allErrors = append(allErrors, fmt.Errorf("invalid configuration: cannot specify both filesystem based and dynamic TLS configuration"))
	} else {
		if cfg.TLSConfig.FilesystemConfigProvided() {
			if cfg.TLSConfig.Filesystem.KeyFile == "" {
				allErrors = append(allErrors, fmt.Errorf("invalid configuration: tlsConfig.filesystem.keyFile (--tls-private-key-file) must be specified when using filesystem based TLS config"))
			}
			if cfg.TLSConfig.Filesystem.CertFile == "" {
				allErrors = append(allErrors, fmt.Errorf("invalid configuration: tlsConfig.filesystem.certFile (--tls-cert-file) must be specified when using filesystem based TLS config"))
			}
		} else if cfg.TLSConfig.DynamicConfigProvided() {
			if cfg.TLSConfig.Dynamic.SecretNamespace == "" {
				allErrors = append(allErrors, fmt.Errorf("invalid configuration: tlsConfig.dynamic.secretNamespace (--dynamic-serving-ca-secret-namespace) must be specified when using dynamic TLS config"))
			}
			if cfg.TLSConfig.Dynamic.SecretName == "" {
				allErrors = append(allErrors, fmt.Errorf("invalid configuration: tlsConfig.dynamic.secretName (--dynamic-serving-ca-secret-name) must be specified when using dynamic TLS config"))
			}
			if len(cfg.TLSConfig.Dynamic.DNSNames) == 0 {
				allErrors = append(allErrors, fmt.Errorf("invalid configuration: tlsConfig.dynamic.dnsNames (--dynamic-serving-dns-names) must be specified when using dynamic TLS config"))
			}
		}
	}
	if cfg.HealthzPort < 0 || cfg.HealthzPort > 65535 {
		allErrors = append(allErrors, fmt.Errorf("invalid configuration: healthzPort must be a valid port number"))
	}
	if cfg.SecurePort < 0 || cfg.SecurePort > 65535 {
		allErrors = append(allErrors, fmt.Errorf("invalid configuration: securePort must be a valid port number"))
	}
	return utilerrors.NewAggregate(allErrors)
}
