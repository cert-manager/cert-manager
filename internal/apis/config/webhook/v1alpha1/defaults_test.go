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

package v1alpha1

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cert-manager/cert-manager/pkg/apis/config/webhook/v1alpha1"
)

func TestWebhookConfigurationDefaults(t *testing.T) {
	tests := []struct {
		name         string
		config       *v1alpha1.WebhookConfiguration
		jsonFilePath string
	}{
		{
			"v1alpha1",
			&v1alpha1.WebhookConfiguration{},
			"testdata/defaults.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetObjectDefaults_WebhookConfiguration(tt.config)

			defaultData, err := json.MarshalIndent(tt.config, "", "\t")
			if err != nil {
				t.Fatal(err)
			}

			if os.Getenv("UPDATE_DEFAULTS") == "true" {
				if err := os.WriteFile(tt.jsonFilePath, defaultData, 0644); err != nil {
					t.Fatal(err)
				}
				t.Log("webhook config api defaults updated")
			}

			expectedData, err := os.ReadFile(tt.jsonFilePath)
			if err != nil {
				t.Fatal(err)
			}

			require.Equal(t, expectedData, defaultData)
		})
	}
}
