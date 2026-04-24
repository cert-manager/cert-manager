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

	"github.com/go-logr/logr"
	logsapi "k8s.io/component-base/logs/api/v1"

	config "github.com/cert-manager/cert-manager/internal/apis/config/webhook"
	"github.com/cert-manager/cert-manager/internal/pem"
	"github.com/cert-manager/cert-manager/pkg/webhook/options"
)

func testCmdCommand(t *testing.T, tempDir string, yaml string, args func(string) []string) (*config.WebhookConfiguration, error) {
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

	var finalConfig *config.WebhookConfiguration

	if err := logsapi.ResetForTest(nil); err != nil {
		t.Error(err)
	}

	cmd := newServerCommand(t.Context(), func(ctx context.Context, cc *config.WebhookConfiguration) error {
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
		expConfig func(string) *config.WebhookConfiguration
	}

	configFromDefaults := func(
		fn func(string, *config.WebhookConfiguration),
	) func(string) *config.WebhookConfiguration {
		defaults, err := options.NewWebhookConfiguration()
		if err != nil {
			t.Error(err)
		}
		return func(tempDir string) *config.WebhookConfiguration {
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
			expConfig: configFromDefaults(func(tempDir string, cc *config.WebhookConfiguration) {
				cc.KubeConfig = "valid"
			}),
		},
		{
			yaml: `
apiVersion: webhook.config.cert-manager.io/v1alpha1
kind: WebhookConfiguration
kubeConfig: "<invalid>"
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath, "--kubeconfig=valid"}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.WebhookConfiguration) {
				cc.KubeConfig = "valid"
			}),
		},
		{
			yaml: `
apiVersion: webhook.config.cert-manager.io/v1alpha1
kind: WebhookConfiguration
kubeConfig: valid
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.WebhookConfiguration) {
				cc.KubeConfig = path.Join(tempDir, "valid")
			}),
		},
		{
			yaml: `
apiVersion: webhook.config.cert-manager.io/v1alpha1
kind: WebhookConfiguration
tlsConfig: {}
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.WebhookConfiguration) {
			}),
		},
		{
			yaml: `
apiVersion: webhook.config.cert-manager.io/v1alpha1
kind: WebhookConfiguration
tlsConfig: nil
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath}
			},
			expError: true,
		},
		{
			yaml: `
apiVersion: webhook.config.cert-manager.io/v1alpha1
kind: WebhookConfiguration
tlsConfig:
    filesystem:
        certFile: aaaa
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath, "--tls-private-key-file=bbbb"}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.WebhookConfiguration) {
				cc.TLSConfig.Filesystem.CertFile = path.Join(tempDir, "aaaa")
				cc.TLSConfig.Filesystem.KeyFile = "bbbb"
			}),
		},
		{
			yaml: `
apiVersion: webhook.config.cert-manager.io/v1alpha1
kind: WebhookConfiguration
logging:
    verbosity: 2
    format: text
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.WebhookConfiguration) {
				cc.Logging.Verbosity = 2
				cc.Logging.Format = "text"
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
	// Restore global size limits after the test so it doesn't leak into the
	// rest of the test binary.
	t.Cleanup(func() {
		pem.SetGlobalSizeLimits(pem.DefaultSizeLimits())
	})

	log := logr.Discard()

	tests := []struct {
		name      string
		config    *config.WebhookConfiguration
		expectErr bool
		errMsg    string
	}{
		{
			name:      "nil configuration",
			config:    nil,
			expectErr: true,
			errMsg:    "webhook configuration is nil",
		},
		{
			name: "valid configuration",
			config: &config.WebhookConfiguration{
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
			config: &config.WebhookConfiguration{
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
			config: &config.WebhookConfiguration{
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

// TestConfigurePEMSizeLimits_AppliedGlobally confirms that a successful call
// propagates the configured values to the global PEM decoder — this is the
// behaviour that makes the admission path use the configured limits.
func TestConfigurePEMSizeLimits_AppliedGlobally(t *testing.T) {
	t.Cleanup(func() {
		pem.SetGlobalSizeLimits(pem.DefaultSizeLimits())
	})

	cfg := &config.WebhookConfiguration{
		PEMSizeLimitsConfig: config.PEMSizeLimitsConfig{
			MaxCertificateSize: 100000,
			MaxPrivateKeySize:  20000,
			MaxChainLength:     200000,
			MaxBundleSize:      400000,
		},
	}

	if err := configurePEMSizeLimits(cfg, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := pem.GetGlobalSizeLimits()
	if got.MaxCertificateSize != 100000 {
		t.Errorf("expected MaxCertificateSize=100000, got %d", got.MaxCertificateSize)
	}
	if got.MaxPrivateKeySize != 20000 {
		t.Errorf("expected MaxPrivateKeySize=20000, got %d", got.MaxPrivateKeySize)
	}
	if got.MaxChainLength != 200000 {
		t.Errorf("expected MaxChainLength=200000, got %d", got.MaxChainLength)
	}
	if got.MaxBundleSize != 400000 {
		t.Errorf("expected MaxBundleSize=400000, got %d", got.MaxBundleSize)
	}
}
