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

	logsapi "k8s.io/component-base/logs/api/v1"

	config "github.com/cert-manager/cert-manager/internal/apis/config/webhook"
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

	cmd := newServerCommand(context.TODO(), func(ctx context.Context, cc *config.WebhookConfiguration) error {
		finalConfig = cc
		return nil
	}, args(tempFilePath))

	cmd.SetErr(io.Discard)
	cmd.SetOut(io.Discard)

	err := cmd.ExecuteContext(context.TODO())
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
