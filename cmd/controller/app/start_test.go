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

package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"testing"

	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
	"github.com/go-logr/logr"
	logsapi "k8s.io/component-base/logs/api/v1"

	"github.com/cert-manager/cert-manager/controller-binary/app/options"
)

func testCmdCommand(t *testing.T, tempDir string, yaml string, args func(string) []string) (*config.ControllerConfiguration, error) {
	var tempFilePath string

	func() {
		tempFile, err := os.CreateTemp(tempDir, "config-*.yaml")
		if err != nil {
			t.Error(err)
		}
		defer tempFile.Close()

		tempFilePath = tempFile.Name()

		if _, err := tempFile.WriteString(yaml); err != nil {
			t.Error(err)
		}
	}()

	var finalConfig *config.ControllerConfiguration

	if err := logsapi.ResetForTest(nil); err != nil {
		t.Error(err)
	}
	cmd := newServerCommand(t.Context(), func(ctx context.Context, cc *config.ControllerConfiguration) error {
		finalConfig = cc
		return nil
	}, args(tempFilePath))

	cmd.SetErr(io.Discard)
	cmd.SetOut(io.Discard)

	err := cmd.ExecuteContext(t.Context())
	return finalConfig, err
}

func TestFlagsAndConfigFile(t *testing.T) {
	type testCase struct {
		yaml      string
		args      func(string) []string
		expError  bool
		expConfig func(string) *config.ControllerConfiguration
	}

	configFromDefaults := func(
		fn func(string, *config.ControllerConfiguration),
	) func(string) *config.ControllerConfiguration {
		defaults, err := options.NewControllerConfiguration()
		if err != nil {
			t.Error(err)
		}
		return func(tempDir string) *config.ControllerConfiguration {
			fn(tempDir, defaults)
			return defaults
		}
	}

	tests := []testCase{
		{
			yaml: ``,
			args: func(tempFilePath string) []string {
				return []string{"--kubeconfig=valid"}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.ControllerConfiguration) {
				cc.KubeConfig = "valid"
			}),
		},
		{
			yaml: `
apiVersion: controller.config.cert-manager.io/v1alpha1
kind: ControllerConfiguration
kubeConfig: "<invalid>"
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath, "--kubeconfig=valid"}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.ControllerConfiguration) {
				cc.KubeConfig = "valid"
			}),
		},
		{
			yaml: `
apiVersion: controller.config.cert-manager.io/v1alpha1
kind: ControllerConfiguration
kubeConfig: valid
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.ControllerConfiguration) {
				cc.KubeConfig = path.Join(tempDir, "valid")
			}),
		},
		{
			yaml: `
apiVersion: controller.config.cert-manager.io/v1alpha1
kind: ControllerConfiguration
ingressShimConfig: {}
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.ControllerConfiguration) {
			}),
		},
		{
			yaml: `
apiVersion: controller.config.cert-manager.io/v1alpha1
kind: ControllerConfiguration
ingressShimConfig: nil
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath}
			},
			expError: true,
		},
		{
			yaml: `
apiVersion: controller.config.cert-manager.io/v1alpha1
kind: ControllerConfiguration
ingressShimConfig:
    defaultIssuerName: aaaa
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath, "--default-issuer-kind=bbbb"}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.ControllerConfiguration) {
				cc.IngressShimConfig.DefaultIssuerName = "aaaa"
				cc.IngressShimConfig.DefaultIssuerKind = "bbbb"
			}),
		},
		{
			yaml: `
apiVersion: controller.config.cert-manager.io/v1alpha1
kind: ControllerConfiguration
logging:
    verbosity: 2
    format: text
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.ControllerConfiguration) {
				cc.Logging.Verbosity = 2
				cc.Logging.Format = "text"
			}),
		},
		{
			yaml: `
apiVersion: controller.config.cert-manager.io/v1alpha1
kind: ControllerConfiguration
ingressShimConfig: {}
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath, "--extra-certificate-annotations", "venafi.cert-manager.io/custom-fields"}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.ControllerConfiguration) {
				cc.IngressShimConfig.ExtraCertificateAnnotations = []string{"venafi.cert-manager.io/custom-fields"}
			}),
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			tempDir := t.TempDir()

			config, err := testCmdCommand(t, tempDir, tc.yaml, tc.args)
			if tc.expError != (err != nil) {
				if err == nil {
					t.Error("expected error, got nil")
				} else {
					t.Errorf("unexpected error: %v", err)
				}
			} else if !tc.expError {
				expConfig := tc.expConfig(tempDir)
				if !reflect.DeepEqual(config, expConfig) {
					t.Errorf("expected config %v but got %v", expConfig, config)
				}
			}
		})
	}
}

func TestConfigurePEMSizeLimits(t *testing.T) {
	// Create a discarding logger for tests
	log := logr.Discard()

	tests := []struct {
		name      string
		config    *config.ControllerConfiguration
		expectErr bool
		errMsg    string
	}{
		{
			name:      "nil configuration",
			config:    nil,
			expectErr: true,
			errMsg:    "controller configuration is nil",
		},
		{
			name: "valid configuration",
			config: &config.ControllerConfiguration{
				PEMSizeLimitsConfig: config.PEMSizeLimitsConfig{
					MaxCertificateSize: 6500,
					MaxPrivateKeySize:  13000,
					MaxChainLength:     10,
					MaxBundleSize:      330000,
				},
			},
			expectErr: false,
		},
		{
			name: "zero certificate size",
			config: &config.ControllerConfiguration{
				PEMSizeLimitsConfig: config.PEMSizeLimitsConfig{
					MaxCertificateSize: 0,
					MaxPrivateKeySize:  13000,
					MaxChainLength:     10,
					MaxBundleSize:      330000,
				},
			},
			expectErr: true,
			errMsg:    "maxCertificateSize must be greater than 0, got 0",
		},
		{
			name: "certificate size larger than bundle size",
			config: &config.ControllerConfiguration{
				PEMSizeLimitsConfig: config.PEMSizeLimitsConfig{
					MaxCertificateSize: 400000,
					MaxPrivateKeySize:  13000,
					MaxChainLength:     10,
					MaxBundleSize:      330000,
				},
			},
			expectErr: true,
			errMsg:    "maxCertificateSize (400000) must not be larger than maxBundleSize (330000)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := configurePEMSizeLimits(tt.config, log)

			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && err.Error() != tt.errMsg {
					t.Errorf("expected error %q, got %q", tt.errMsg, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseAndValidateMetricLabels(t *testing.T) {
	tests := []struct {
		name       string
		input      map[string]string
		wantResult map[string]map[string]string
		wantErrors bool
	}{
		{
			name: "nil input returns nil",
		},
		{
			name:       "empty input returns empty map",
			input:      map[string]string{},
			wantResult: map[string]map[string]string{},
		},
		{
			name: "valid single metric label",
			input: map[string]string{
				"certmanager_certificate_ready_status:environment": "production",
			},
			wantResult: map[string]map[string]string{
				"certmanager_certificate_ready_status": {"environment": "production"},
			},
		},
		{
			name: "valid multiple labels for same metric",
			input: map[string]string{
				"certmanager_certificate_ready_status:env":    "prod",
				"certmanager_certificate_ready_status:region": "useast",
			},
			wantResult: map[string]map[string]string{
				"certmanager_certificate_ready_status": {"env": "prod", "region": "useast"},
			},
		},
		{
			name: "valid labels for different metrics",
			input: map[string]string{
				"certmanager_certificate_ready_status:env":                 "prod",
				"certmanager_certificate_expiration_timestamp_seconds:env": "staging",
			},
			wantResult: map[string]map[string]string{
				"certmanager_certificate_ready_status":                 {"env": "prod"},
				"certmanager_certificate_expiration_timestamp_seconds": {"env": "staging"},
			},
		},
		{
			name: "label key with underscores is allowed",
			input: map[string]string{
				"certmanager_certificate_ready_status:my_key": "value",
			},
			wantResult: map[string]map[string]string{
				"certmanager_certificate_ready_status": {"my_key": "value"},
			},
		},
		{
			name: "must match metric:label=value format - missing colon",
			input: map[string]string{
				"metric_only": "value",
			},
			wantErrors: true,
		},
		{
			name: "must match metric:label=value format - multiple colons",
			input: map[string]string{
				"metric:label:extra": "value",
			},
			wantErrors: true,
		},
		{
			name: "label value must not be empty",
			input: map[string]string{
				"certmanager_certificate_ready_status:label": "",
			},
			wantErrors: true,
		},
		{
			name: "metric name with underscores is allowed",
			input: map[string]string{
				"certmanager_certificate_ready_status:label": "value",
			},
			wantResult: map[string]map[string]string{
				"certmanager_certificate_ready_status": {"label": "value"},
			},
		},
		{
			name: "unknown metric name is rejected",
			input: map[string]string{
				"unknown_metric:label": "value",
			},
			wantErrors: true,
		},
		{
			name: "metric name must be alphanumeric - contains special char",
			input: map[string]string{
				"my-metric:label": "value",
			},
			wantErrors: true,
		},
		{
			name: "label value must be alphanumeric",
			input: map[string]string{
				"certmanager_certificate_ready_status:label": "value-with-dashes",
			},
			wantErrors: true,
		},
		{
			name: "label key must not start with a number",
			input: map[string]string{
				"certmanager_certificate_ready_status:1label": "value",
			},
			wantErrors: true,
		},
		{
			name: "forbidden label key - name",
			input: map[string]string{
				"certmanager_certificate_ready_status:name": "value",
			},
			wantErrors: true,
		},
		{
			name: "forbidden label key - namespace",
			input: map[string]string{
				"certmanager_certificate_ready_status:namespace": "value",
			},
			wantErrors: true,
		},
		{
			name: "forbidden label key - issuer_name",
			input: map[string]string{
				"certmanager_certificate_ready_status:issuer_name": "value",
			},
			wantErrors: true,
		},
		{
			name: "forbidden label key - issuer_kind",
			input: map[string]string{
				"certmanager_certificate_ready_status:issuer_kind": "value",
			},
			wantErrors: true,
		},
		{
			name: "forbidden label key - issuer_group",
			input: map[string]string{
				"certmanager_certificate_ready_status:issuer_group": "value",
			},
			wantErrors: true,
		},
		{
			name: "maximum 10 labels per metric",
			input: func() map[string]string {
				m := make(map[string]string)
				for i := range 11 {
					m[fmt.Sprintf("certmanager_certificate_ready_status:label%d", i)] = fmt.Sprintf("value%d", i)
				}
				return m
			}(),
			wantErrors: true,
		},
		{
			name: "exactly 10 labels per metric is allowed",
			input: func() map[string]string {
				m := make(map[string]string)
				for i := range 10 {
					m[fmt.Sprintf("certmanager_certificate_ready_status:label%d", i)] = fmt.Sprintf("value%d", i)
				}
				return m
			}(),
			wantResult: func() map[string]map[string]string {
				r := map[string]map[string]string{"certmanager_certificate_ready_status": {}}
				for i := range 10 {
					r["certmanager_certificate_ready_status"][fmt.Sprintf("label%d", i)] = fmt.Sprintf("value%d", i)
				}
				return r
			}(),
		},
		{
			name: "duplicate label keys silently overwrite",
			input: func() map[string]string {
				m := map[string]string{"certmanager_certificate_ready_status:env": "prod"}
				m["certmanager_certificate_ready_status:env"] = "staging"
				return m
			}(),
			wantResult: map[string]map[string]string{
				"certmanager_certificate_ready_status": {"env": "staging"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, errs := parseAndValidateMetricLabels(tt.input, nil)

			if tt.wantErrors && len(errs) == 0 {
				t.Errorf("expected errors, got none")
			}
			if !tt.wantErrors && len(errs) > 0 {
				t.Errorf("unexpected errors: %v", errs)
			}
			if tt.wantResult != nil && !reflect.DeepEqual(got, tt.wantResult) {
				t.Errorf("expected result %v, got %v", tt.wantResult, got)
			}
		})
	}
}
