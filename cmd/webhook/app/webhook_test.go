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
	"testing"

	"github.com/cert-manager/cert-manager/cmd/webhook/app/options"
)

// Test to ensure flags take precedence over config options.
func TestWebhookConfigFlagPrecedence_FlagsTakePrecedence(t *testing.T) {
	cfg, err := options.NewWebhookConfiguration()
	if err != nil {
		t.Fatal(err)
	}

	cfg.KubeConfig = "<invalid>"
	if err := webhookConfigFlagPrecedence(cfg, []string{"--kubeconfig=valid"}); err != nil {
		t.Fatal(err)
	}

	if cfg.KubeConfig != "valid" {
		t.Errorf("unexpected field value %q, expected %q", cfg.KubeConfig, "valid")
	}
}

// Test to ensure that when flags are not provided, config provided values are preserved.
func TestWebhookConfigFlagPrecedence_ConfigPersistsWithoutFlags(t *testing.T) {
	cfg, err := options.NewWebhookConfiguration()
	if err != nil {
		t.Fatal(err)
	}

	cfg.KubeConfig = "valid"
	if err := webhookConfigFlagPrecedence(cfg, []string{}); err != nil {
		t.Fatal(err)
	}

	if cfg.KubeConfig != "valid" {
		t.Errorf("unexpected field value %q, expected %q", cfg.KubeConfig, "valid")
	}
}
