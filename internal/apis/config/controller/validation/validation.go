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
	"net"
	"net/url"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	logsapi "k8s.io/component-base/logs/api/v1"

	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
	defaults "github.com/cert-manager/cert-manager/internal/apis/config/controller/v1alpha1"
	sharedvalidation "github.com/cert-manager/cert-manager/internal/apis/config/shared/validation"
)

func ValidateControllerConfiguration(cfg *config.ControllerConfiguration, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList

	allErrors = append(allErrors, logsapi.Validate(&cfg.Logging, nil, fldPath.Child("logging"))...)
	allErrors = append(allErrors, sharedvalidation.ValidateTLSConfig(&cfg.MetricsTLSConfig, fldPath.Child("metricsTLSConfig"))...)

	if cfg.LeaderElectionConfig.Enabled && cfg.LeaderElectionConfig.HealthzTimeout <= 0 {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("leaderElectionConfig").Child("healthzTimeout"), cfg.LeaderElectionConfig.HealthzTimeout, "must be higher than 0"))
	}
	allErrors = append(allErrors, sharedvalidation.ValidateLeaderElectionConfig(&cfg.LeaderElectionConfig.LeaderElectionConfig, fldPath.Child("leaderElectionConfig"))...)

	if len(cfg.IngressShimConfig.DefaultIssuerKind) == 0 {
		allErrors = append(allErrors, field.Required(fldPath.Child("ingressShimConfig").Child("defaultIssuerKind"), "must not be empty"))
	}

	if cfg.KubernetesAPIBurst <= 0 {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("kubernetesAPIBurst"), cfg.KubernetesAPIBurst, "must be higher than 0"))
	}

	if cfg.KubernetesAPIQPS <= 0 {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("kubernetesAPIQPS"), cfg.KubernetesAPIQPS, "must be higher than 0"))
	}

	if float32(cfg.KubernetesAPIBurst) < cfg.KubernetesAPIQPS {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("kubernetesAPIBurst"), cfg.KubernetesAPIBurst, "must be higher or equal to kubernetesAPIQPS"))
	}

	for i, server := range cfg.ACMEHTTP01Config.SolverNameservers {
		// ensure all servers have a port number
		_, _, err := net.SplitHostPort(server)
		if err != nil {
			allErrors = append(allErrors, field.Invalid(fldPath.Child("acmeHTTP01Config").Child("solverNameservers").Index(i), server, "must be in the format <ip address>:<port>"))
		}
	}

	for i, server := range cfg.ACMEDNS01Config.RecursiveNameservers {
		// ensure all servers follow one of the following formats:
		// - <ip address>:<port>
		// - https://<DoH RFC 8484 server address>

		if strings.HasPrefix(server, "https://") {
			if u, err := url.ParseRequestURI(server); err != nil || u.Scheme != "https" || u.Host == "" {
				allErrors = append(allErrors, field.Invalid(fldPath.Child("acmeDNS01Config").Child("recursiveNameservers").Index(i), server, "must be in the format https://<DoH RFC 8484 server address>"))
			}
		} else {
			if _, _, err := net.SplitHostPort(server); err != nil {
				allErrors = append(allErrors, field.Invalid(fldPath.Child("acmeDNS01Config").Child("recursiveNameservers").Index(i), server, "must be in the format <ip address>:<port>"))
			}
		}
	}

	allControllersSet := sets.NewString(defaults.AllControllers...)
	for i, controller := range cfg.Controllers {
		if controller == "*" {
			continue
		}

		controller = strings.TrimPrefix(controller, "-")
		if !allControllersSet.Has(controller) {
			allErrors = append(allErrors, field.Invalid(fldPath.Child("controllers").Index(i), controller, "is not in the list of known controllers"))
		}
	}

	return allErrors
}
