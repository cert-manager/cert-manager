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
	"k8s.io/apimachinery/pkg/util/validation/field"
	logsapi "k8s.io/component-base/logs/api/v1"

	sharedvalidation "github.com/cert-manager/cert-manager/internal/apis/config/shared/validation"
	config "github.com/cert-manager/cert-manager/internal/apis/config/webhook"
)

func ValidateWebhookConfiguration(cfg *config.WebhookConfiguration, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList

	allErrors = append(allErrors, logsapi.Validate(&cfg.Logging, nil, fldPath.Child("logging"))...)
	allErrors = append(allErrors, sharedvalidation.ValidateTLSConfig(&cfg.TLSConfig, fldPath.Child("tlsConfig"))...)

	if cfg.HealthzPort < 0 || cfg.HealthzPort > 65535 {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("healthzPort"), cfg.HealthzPort, "must be a valid port number"))
	}
	if cfg.SecurePort < 0 || cfg.SecurePort > 65535 {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("securePort"), cfg.SecurePort, "must be a valid port number"))
	}

	return allErrors
}
