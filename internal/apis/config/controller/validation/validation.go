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
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
	defaults "github.com/cert-manager/cert-manager/internal/apis/config/controller/v1alpha1"
)

func ValidateControllerConfiguration(cfg *config.ControllerConfiguration) error {
	var allErrors []error

	if cfg.MetricsTLSConfig.FilesystemConfigProvided() && cfg.MetricsTLSConfig.DynamicConfigProvided() {
		allErrors = append(allErrors, fmt.Errorf("invalid configuration: cannot specify both filesystem based and dynamic TLS configuration"))
	} else {
		if cfg.MetricsTLSConfig.FilesystemConfigProvided() {
			if cfg.MetricsTLSConfig.Filesystem.KeyFile == "" {
				allErrors = append(allErrors, fmt.Errorf("invalid configuration: metricsTLSConfig.filesystem.keyFile (--metrics-tls-private-key-file) must be specified when using filesystem based TLS config"))
			}
			if cfg.MetricsTLSConfig.Filesystem.CertFile == "" {
				allErrors = append(allErrors, fmt.Errorf("invalid configuration: metricsTLSConfig.filesystem.certFile (--metrics-tls-cert-file) must be specified when using filesystem based TLS config"))
			}
		} else if cfg.MetricsTLSConfig.DynamicConfigProvided() {
			if cfg.MetricsTLSConfig.Dynamic.SecretNamespace == "" {
				allErrors = append(allErrors, fmt.Errorf("invalid configuration: metricsTLSConfig.dynamic.secretNamespace (--metrics-dynamic-serving-ca-secret-namespace) must be specified when using dynamic TLS config"))
			}
			if cfg.MetricsTLSConfig.Dynamic.SecretName == "" {
				allErrors = append(allErrors, fmt.Errorf("invalid configuration: metricsTLSConfig.dynamic.secretName (--metrics-dynamic-serving-ca-secret-name) must be specified when using dynamic TLS config"))
			}
			if len(cfg.MetricsTLSConfig.Dynamic.DNSNames) == 0 {
				allErrors = append(allErrors, fmt.Errorf("invalid configuration: metricsTLSConfig.dynamic.dnsNames (--metrics-dynamic-serving-dns-names) must be specified when using dynamic TLS config"))
			}
		}
	}

	if len(cfg.IngressShimConfig.DefaultIssuerKind) == 0 {
		allErrors = append(allErrors, errors.New("the --default-issuer-kind flag must not be empty"))
	}

	if cfg.KubernetesAPIBurst <= 0 {
		allErrors = append(allErrors, fmt.Errorf("invalid value for kube-api-burst: %v must be higher than 0", cfg.KubernetesAPIBurst))
	}

	if cfg.KubernetesAPIQPS <= 0 {
		allErrors = append(allErrors, fmt.Errorf("invalid value for kube-api-qps: %v must be higher than 0", cfg.KubernetesAPIQPS))
	}

	if float32(cfg.KubernetesAPIBurst) < cfg.KubernetesAPIQPS {
		allErrors = append(allErrors, fmt.Errorf("invalid value for kube-api-burst: %v must be higher or equal to kube-api-qps: %v", cfg.KubernetesAPIQPS, cfg.KubernetesAPIQPS))
	}

	for _, server := range cfg.ACMEHTTP01Config.SolverNameservers {
		// ensure all servers have a port number
		_, _, err := net.SplitHostPort(server)
		if err != nil {
			allErrors = append(allErrors, fmt.Errorf("invalid DNS server (%v): %v", err, server))
		}
	}

	for _, server := range cfg.ACMEDNS01Config.RecursiveNameservers {
		// ensure all servers follow one of the following formats:
		// - <ip address>:<port>
		// - https://<DoH RFC 8484 server address>

		if strings.HasPrefix(server, "https://") {
			_, err := url.ParseRequestURI(server)
			if err != nil {
				allErrors = append(allErrors, fmt.Errorf("invalid DNS server (%v): %v", err, server))
			}
		} else {
			_, _, err := net.SplitHostPort(server)
			if err != nil {
				allErrors = append(allErrors, fmt.Errorf("invalid DNS server (%v): %v", err, server))
			}
		}
	}

	controllerErrors := []error{}
	allControllersSet := sets.NewString(defaults.AllControllers...)
	for _, controller := range cfg.Controllers {
		if controller == "*" {
			continue
		}

		controller = strings.TrimPrefix(controller, "-")
		if !allControllersSet.Has(controller) {
			controllerErrors = append(controllerErrors, fmt.Errorf("%q is not in the list of known controllers", controller))
		}
	}
	if len(controllerErrors) > 0 {
		allErrors = append(allErrors, fmt.Errorf("validation failed for '--controllers': %v", controllerErrors))
	}

	return utilerrors.NewAggregate(allErrors)
}
