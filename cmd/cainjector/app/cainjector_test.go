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

	"github.com/cert-manager/cert-manager/cainjector-binary/app/options"
	config "github.com/cert-manager/cert-manager/internal/apis/config/cainjector"
)

func testCmdCommand(t *testing.T, tempDir string, yaml string, args func(string) []string) (*config.CAInjectorConfiguration, error) {
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

	var finalConfig *config.CAInjectorConfiguration

	if err := logsapi.ResetForTest(nil); err != nil {
		t.Error(err)
	}

	cmd := newCAInjectorCommand(context.TODO(), func(ctx context.Context, cc *config.CAInjectorConfiguration) error {
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
		expConfig func(string) *config.CAInjectorConfiguration
	}

	configFromDefaults := func(
		fn func(string, *config.CAInjectorConfiguration),
	) func(string) *config.CAInjectorConfiguration {
		defaults, err := options.NewCAInjectorConfiguration()
		if err != nil {
			t.Error(err)
		}
		return func(tempDir string) *config.CAInjectorConfiguration {
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
			expConfig: configFromDefaults(func(tempDir string, cc *config.CAInjectorConfiguration) {
				cc.KubeConfig = "valid"
			}),
		},
		{
			yaml: `
apiVersion: cainjector.config.cert-manager.io/v1alpha1
kind: CAInjectorConfiguration
kubeConfig: "<invalid>"
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath, "--kubeconfig=valid"}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.CAInjectorConfiguration) {
				cc.KubeConfig = "valid"
			}),
		},
		{
			yaml: `
apiVersion: cainjector.config.cert-manager.io/v1alpha1
kind: CAInjectorConfiguration
kubeConfig: valid
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.CAInjectorConfiguration) {
				cc.KubeConfig = path.Join(tempDir, "valid")
			}),
		},
		{
			yaml: `
apiVersion: cainjector.config.cert-manager.io/v1alpha1
kind: CAInjectorConfiguration
enableDataSourceConfig: {}
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.CAInjectorConfiguration) {
			}),
		},
		{
			yaml: `
apiVersion: cainjector.config.cert-manager.io/v1alpha1
kind: CAInjectorConfiguration
enableDataSourceConfig: nil
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath}
			},
			expError: true,
		},
		{
			yaml: `
apiVersion: cainjector.config.cert-manager.io/v1alpha1
kind: CAInjectorConfiguration
enableInjectableConfig:
    validatingWebhookConfigurations: false
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath, "--enable-mutatingwebhookconfigurations-injectable=false"}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.CAInjectorConfiguration) {
				cc.EnableInjectableConfig.ValidatingWebhookConfigurations = false
				cc.EnableInjectableConfig.MutatingWebhookConfigurations = false
			}),
		},
		{
			yaml: `
apiVersion: cainjector.config.cert-manager.io/v1alpha1
kind: CAInjectorConfiguration
logging:
    verbosity: 2
    format: text
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.CAInjectorConfiguration) {
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
