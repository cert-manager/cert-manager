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

	shared "github.com/cert-manager/cert-manager/internal/apis/config/shared"
)

func ValidateTLSConfig(tlsConfig *shared.TLSConfig, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList

	if tlsConfig.FilesystemConfigProvided() && tlsConfig.DynamicConfigProvided() {
		allErrors = append(allErrors, field.Invalid(fldPath, tlsConfig, "cannot specify both filesystem based and dynamic TLS configuration"))
	} else {
		if tlsConfig.FilesystemConfigProvided() {
			fileSystemPath := fldPath.Child("filesystem")
			if tlsConfig.Filesystem.KeyFile == "" {
				allErrors = append(allErrors, field.Required(fileSystemPath.Child("keyFile"), "must be specified when using filesystem based TLS config"))
			}
			if tlsConfig.Filesystem.CertFile == "" {
				allErrors = append(allErrors, field.Required(fileSystemPath.Child("certFile"), "must be specified when using filesystem based TLS config"))
			}
		} else if tlsConfig.DynamicConfigProvided() {
			dynamicPath := fldPath.Child("dynamic")
			if tlsConfig.Dynamic.SecretNamespace == "" {
				allErrors = append(allErrors, field.Required(dynamicPath.Child("secretNamespace"), "must be specified when using dynamic TLS config"))
			}
			if tlsConfig.Dynamic.SecretName == "" {
				allErrors = append(allErrors, field.Required(dynamicPath.Child("secretName"), "must be specified when using dynamic TLS config"))
			}
			if len(tlsConfig.Dynamic.DNSNames) == 0 {
				allErrors = append(allErrors, field.Required(dynamicPath.Child("dnsNames"), "must be specified when using dynamic TLS config"))
			}
		}
	}

	return allErrors
}

func ValidateLeaderElectionConfig(leaderElectionConfig *shared.LeaderElectionConfig, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList

	if !leaderElectionConfig.Enabled {
		return allErrors
	}

	if leaderElectionConfig.LeaseDuration <= 0 {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("leaseDuration"), leaderElectionConfig.LeaseDuration, "must be greater than 0"))
	}
	if leaderElectionConfig.RenewDeadline <= 0 {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("renewDeadline"), leaderElectionConfig.RenewDeadline, "must be greater than 0"))
	}
	if leaderElectionConfig.RetryPeriod <= 0 {
		allErrors = append(allErrors, field.Invalid(fldPath.Child("retryPeriod"), leaderElectionConfig.RetryPeriod, "must be greater than 0"))
	}

	return allErrors
}
