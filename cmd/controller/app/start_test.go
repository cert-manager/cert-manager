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

	"github.com/cert-manager/cert-manager/controller-binary/app/options"
	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
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
	cmd := newServerCommand(context.TODO(), func(ctx context.Context, cc *config.ControllerConfiguration) error {
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
