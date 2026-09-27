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
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	logsapi "k8s.io/component-base/logs/api/v1"

	issuervalidationutil "github.com/cert-manager/cert-manager/internal/apis/certmanager/validation/util"
	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
	defaults "github.com/cert-manager/cert-manager/internal/apis/config/controller/v1alpha1"
	sharedvalidation "github.com/cert-manager/cert-manager/internal/apis/config/shared/validation"
)

func ValidateControllerConfiguration(cfg *config.ControllerConfiguration, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList

	allErrors = append(allErrors, logsapi.Validate(&cfg.Logging, nil, fldPath.Child("logging"))...)
	allErrors = append(allErrors, sharedvalidation.ValidateTLSConfig(&cfg.MetricsTLSConfig, fldPath.Child("metricsTLSConfig"))...)

	if cfg.LeaderElectionConfig.Enabled && cfg.LeaderElectionConfig.HealthzTimeout <= 0 {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("leaderElectionConfig").Child("healthzTimeout"), cfg.LeaderElectionConfig.HealthzTimeout, "must be greater than 0"))
	}
	allErrors = append(allErrors, sharedvalidation.ValidateLeaderElectionConfig(&cfg.LeaderElectionConfig.LeaderElectionConfig, fldPath.Child("leaderElectionConfig"))...)

	if len(cfg.IngressShimConfig.DefaultIssuerKind) == 0 {
		allErrors = append(allErrors, field.Required(fldPath.Child("ingressShimConfig").Child("defaultIssuerKind"), "must not be empty"))
	}

	if cfg.KubernetesAPIBurst < -1 {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("kubernetesAPIBurst"), cfg.KubernetesAPIBurst, "must be greater than or equal to -1"))
	}

	if cfg.KubernetesAPIQPS < -1 {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("kubernetesAPIQPS"), cfg.KubernetesAPIQPS, "must be greater than or equal to -1"))
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
		if err := issuervalidationutil.ValidDNS01Nameserver(server); err != nil {
			allErrors = append(allErrors, field.Invalid(fldPath.Child("acmeDNS01Config").Child("recursiveNameservers").Index(i), server, err.Error()))
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

	allErrors = append(allErrors, validatePEMSizeLimitsConfig(&cfg.PEMSizeLimitsConfig, fldPath.Child("pemSizeLimitsConfig"))...)

	allErrors = append(allErrors, validateCertificateRequestBackoffConfig(&cfg.CertificateRequestMinimumBackoffDuration, &cfg.CertificateRequestMaximumBackoffDuration, fldPath)...)

	return allErrors
}

func validatePEMSizeLimitsConfig(cfg *config.PEMSizeLimitsConfig, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList

	if cfg.MaxCertificateSize <= 0 {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("maxCertificateSize"), cfg.MaxCertificateSize, "must be greater than 0"))
	}

	if cfg.MaxPrivateKeySize <= 0 {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("maxPrivateKeySize"), cfg.MaxPrivateKeySize, "must be greater than 0"))
	}

	if cfg.MaxChainLength <= 0 {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("maxChainLength"), cfg.MaxChainLength, "must be greater than 0"))
	}

	if cfg.MaxBundleSize <= 0 {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("maxBundleSize"), cfg.MaxBundleSize, "must be greater than 0"))
	}

	// Validate that MaxCertificateSize is not larger than MaxBundleSize
	if cfg.MaxCertificateSize > cfg.MaxBundleSize {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("maxCertificateSize"), cfg.MaxCertificateSize, "must not be larger than maxBundleSize"))
	}

	// Validate that MaxChainLength is not larger than MaxBundleSize
	if cfg.MaxChainLength > cfg.MaxBundleSize {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("maxChainLength"), cfg.MaxChainLength, "must not exceed maxBundleSize"))
	}

	return allErrors
}

func validateCertificateRequestBackoffConfig(minBackoff, maxBackoff *time.Duration, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList

	// Validate minimum backoff. Negative values are rejected; zero is
	// handled by SetDefaults_ControllerConfiguration before validation runs.
	if *minBackoff < 0 {
		allErrors = append(allErrors, field.Invalid(
			fldPath.Child("certificateRequestMinimumBackoffDuration"),
			minBackoff.String(),
			"must not be negative",
		))
	}

	// Validate maximum backoff. Negative values are rejected; zero is
	// handled by SetDefaults_ControllerConfiguration before validation runs.
	if *maxBackoff < 0 {
		allErrors = append(allErrors, field.Invalid(
			fldPath.Child("certificateRequestMaximumBackoffDuration"),
			maxBackoff.String(),
			"must not be negative",
		))
	}

	// Validate max >= min (only if both are individually valid)
	if *minBackoff > 0 && *maxBackoff > 0 && *maxBackoff < *minBackoff {
		allErrors = append(allErrors, field.Invalid(
			fldPath.Child("certificateRequestMaximumBackoffDuration"),
			maxBackoff.String(),
			"must be greater than or equal to certificateRequestMinimumBackoffDuration",
		))
	}

	return allErrors
}
