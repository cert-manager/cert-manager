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

	config "github.com/cert-manager/cert-manager/internal/apis/config/cainjector"
	"github.com/cert-manager/cert-manager/internal/apis/config/shared"
)

func TestValidateCAInjectorConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		config *config.CAInjectorConfiguration
		errs   func(*config.CAInjectorConfiguration) field.ErrorList
	}{
		{
			"with valid config",
			&config.CAInjectorConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
			},
			nil,
		},
		{
			"with invalid logging config",
			&config.CAInjectorConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "unknown",
				},
			},
			func(wc *config.CAInjectorConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("logging.format"), wc.Logging.Format, "Unsupported log format"),
				}
			},
		},
		{
			"with invalid leader election config",
			&config.CAInjectorConfiguration{
				Logging: logsapi.LoggingConfiguration{
					Format: "text",
				},
				LeaderElectionConfig: shared.LeaderElectionConfig{
					Enabled: true,
				},
			},
			func(cc *config.CAInjectorConfiguration) field.ErrorList {
				return field.ErrorList{
					field.Invalid(field.NewPath("leaderElectionConfig.leaseDuration"), cc.LeaderElectionConfig.LeaseDuration, "must be greater than 0"),
					field.Invalid(field.NewPath("leaderElectionConfig.renewDeadline"), cc.LeaderElectionConfig.RenewDeadline, "must be greater than 0"),
					field.Invalid(field.NewPath("leaderElectionConfig.retryPeriod"), cc.LeaderElectionConfig.RetryPeriod, "must be greater than 0"),
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errList := ValidateCAInjectorConfiguration(tt.config, nil)
			var expErrs field.ErrorList
			if tt.errs != nil {
				expErrs = tt.errs(tt.config)
			}
			assert.ElementsMatch(t, expErrs, errList)
		})
	}
}
