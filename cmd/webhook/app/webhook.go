/*
Copyright 2020 The cert-manager Authors.

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
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	config "github.com/cert-manager/cert-manager/internal/apis/config/webhook"
	"github.com/cert-manager/cert-manager/internal/apis/config/webhook/validation"
	cmwebhook "github.com/cert-manager/cert-manager/internal/webhook"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/pkg/util/configfile"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	webhookconfigfile "github.com/cert-manager/cert-manager/pkg/webhook/configfile"
	"github.com/cert-manager/cert-manager/pkg/webhook/options"
)

const componentWebhook = "webhook"

func NewServerCommand(ctx context.Context) *cobra.Command {
	return newServerCommand(
		ctx,
		func(ctx context.Context, webhookConfig *config.WebhookConfiguration) error {
			log := logf.FromContext(ctx, componentWebhook)

			srv, err := cmwebhook.NewCertManagerWebhookServer(log, *webhookConfig)
			if err != nil {
				return err
			}

			return srv.Run(ctx)
		},
		os.Args[1:],
	)
}

func newServerCommand(
	setupCtx context.Context,
	run func(context.Context, *config.WebhookConfiguration) error,
	allArgs []string,
) *cobra.Command {
	log := logf.FromContext(setupCtx, componentWebhook)

	webhookFlags := options.NewWebhookFlags()
	webhookConfig, err := options.NewWebhookConfiguration()
	if err != nil {
		log.Error(err, "Failed to create new webhook configuration")
		os.Exit(1)
	}

	cmd := &cobra.Command{
		Use:   componentWebhook,
		Short: fmt.Sprintf("Webhook component providing API validation, mutation and conversion functionality for cert-manager (%s) (%s)", util.AppVersion, util.AppGitCommit),
		Long: `
cert-manager is a Kubernetes addon to automate the management and issuance of
TLS certificates from various issuing sources.

The webhook component provides API validation, mutation and conversion
functionality for cert-manager.`,

		SilenceErrors: true, // We already log errors in main.go
		SilenceUsage:  true, // Don't print usage on every error

		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := loadConfigFromFile(
				cmd, allArgs, webhookFlags.Config, webhookConfig,
				func() error {
					// set feature gates from initial flags-based config
					if err := utilfeature.DefaultMutableFeatureGate.SetFromMap(webhookConfig.FeatureGates); err != nil {
						return fmt.Errorf("failed to set feature gates from initial flags-based config: %w", err)
					}

					return nil
				},
			); err != nil {
				return err
			}

			if err := validation.ValidateWebhookConfiguration(webhookConfig, nil); len(err) > 0 {
				return fmt.Errorf("error validating flags: %w", err.ToAggregate())
			}

			// ValidateWebhookConfiguration should already have validated the
			// logging flags, the logging API does not have an Apply-only function
			// so we validate again here. This should not catch any validation errors
			// anymore.
			if err := logf.ValidateAndApply(&webhookConfig.Logging); err != nil {
				return fmt.Errorf("failed to validate webhook logging flags: %w", err)
			}

			return nil
		},
		// nolint:contextcheck // False positive
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd.Context(), webhookConfig)
		},
	}

	webhookFlags.AddFlags(cmd.Flags())
	options.AddConfigFlags(cmd.Flags(), webhookConfig)

	// explicitly set provided args in case it does not equal os.Args[:1],
	// eg. when running tests
	cmd.SetArgs(allArgs)

	return cmd
}

// loadConfigFromFile loads the configuration from the provided config file
// path, if one is provided. After loading the config file, the flags are
// re-parsed to ensure that any flags provided to the command line override
// those provided in the config file.
// The newConfigHook is called when the options have been loaded from the
// flags (but not yet the config file) and is re-called after the config file
// has been loaded. This allows us to use the feature flags set by the flags
// while loading the config file.
func loadConfigFromFile(
	cmd *cobra.Command,
	allArgs []string,
	configFilePath string,
	cfg *config.WebhookConfiguration,
	newConfigHook func() error,
) error {
	if err := newConfigHook(); err != nil {
		return err
	}

	if len(configFilePath) > 0 {
		// compute absolute path based on current working dir
		webhookConfigFile, err := filepath.Abs(configFilePath)
		if err != nil {
			return fmt.Errorf("failed to load config file %s, error %v", configFilePath, err)
		}

		loader, err := configfile.NewConfigurationFSLoader(nil, webhookConfigFile)
		if err != nil {
			return fmt.Errorf("failed to load config file %s, error %v", configFilePath, err)
		}

		webhookConfigFromFile := webhookconfigfile.New()
		if err := loader.Load(webhookConfigFromFile); err != nil {
			return fmt.Errorf("failed to load config file %s, error %v", configFilePath, err)
		}

		webhookConfigFromFile.Config.DeepCopyInto(cfg)

		_, args, err := cmd.Root().Find(allArgs)
		if err != nil {
			return fmt.Errorf("failed to re-parse flags: %w", err)
		}

		if err := cmd.ParseFlags(args); err != nil {
			return fmt.Errorf("failed to re-parse flags: %w", err)
		}

		if err := newConfigHook(); err != nil {
			return err
		}
	}

	return nil
}
