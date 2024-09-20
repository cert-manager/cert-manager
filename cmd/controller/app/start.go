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

	"github.com/cert-manager/cert-manager/controller-binary/app/options"
	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
	"github.com/cert-manager/cert-manager/internal/apis/config/controller/validation"
	controllerconfigfile "github.com/cert-manager/cert-manager/pkg/controller/configfile"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/pkg/util/configfile"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"

	_ "github.com/cert-manager/cert-manager/pkg/controller/acmechallenges"
	_ "github.com/cert-manager/cert-manager/pkg/controller/acmeorders"
	_ "github.com/cert-manager/cert-manager/pkg/controller/certificate-shim/gateways"
	_ "github.com/cert-manager/cert-manager/pkg/controller/certificate-shim/ingresses"
	_ "github.com/cert-manager/cert-manager/pkg/controller/certificates/trigger"
	_ "github.com/cert-manager/cert-manager/pkg/controller/clusterissuers"
	_ "github.com/cert-manager/cert-manager/pkg/controller/issuers"
	_ "github.com/cert-manager/cert-manager/pkg/issuer/acme"
	_ "github.com/cert-manager/cert-manager/pkg/issuer/ca"
	_ "github.com/cert-manager/cert-manager/pkg/issuer/selfsigned"
	_ "github.com/cert-manager/cert-manager/pkg/issuer/vault"
	_ "github.com/cert-manager/cert-manager/pkg/issuer/venafi"
)

const componentController = "controller"

func NewServerCommand(ctx context.Context) *cobra.Command {
	return newServerCommand(
		ctx,
		Run,
		os.Args[1:],
	)
}

func newServerCommand(
	setupCtx context.Context,
	run func(context.Context, *config.ControllerConfiguration) error,
	allArgs []string,
) *cobra.Command {
	log := logf.FromContext(setupCtx, componentController)

	controllerFlags := options.NewControllerFlags()
	controllerConfig, err := options.NewControllerConfiguration()
	if err != nil {
		log.Error(err, "Failed to create new controller configuration")
		os.Exit(1)
	}

	cmd := &cobra.Command{
		Use:   componentController,
		Short: fmt.Sprintf("Automated TLS controller for Kubernetes (%s) (%s)", util.AppVersion, util.AppGitCommit),
		Long: `
cert-manager is a Kubernetes addon to automate the management and issuance of
TLS certificates from various issuing sources.

It will ensure certificates are valid and up to date periodically, and attempt
to renew certificates at an appropriate time before expiry.`,

		SilenceErrors: true, // We already log errors in main.go
		SilenceUsage:  true, // Don't print usage on every error

		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := loadConfigFromFile(
				cmd, allArgs, controllerFlags.Config, controllerConfig,
				func() error {
					// set feature gates from initial flags-based config
					if err := utilfeature.DefaultMutableFeatureGate.SetFromMap(controllerConfig.FeatureGates); err != nil {
						return fmt.Errorf("failed to set feature gates from initial flags-based config: %w", err)
					}

					return nil
				},
			); err != nil {
				return err
			}

			if err := validation.ValidateControllerConfiguration(controllerConfig, nil); len(err) > 0 {
				return fmt.Errorf("error validating flags: %w", err.ToAggregate())
			}

			// ValidateControllerConfiguration should already have validated the
			// logging flags, the logging API does not have an Apply-only function
			// so we validate again here. This should not catch any validation errors
			// anymore.
			if err := logf.ValidateAndApply(&controllerConfig.Logging); err != nil {
				return fmt.Errorf("failed to validate controller logging flags: %w", err)
			}

			return nil
		},
		// nolint:contextcheck // False positive
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd.Context(), controllerConfig)
		},
	}

	controllerFlags.AddFlags(cmd.Flags())
	options.AddConfigFlags(cmd.Flags(), controllerConfig)

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
	cfg *config.ControllerConfiguration,
	newConfigHook func() error,
) error {
	if err := newConfigHook(); err != nil {
		return err
	}

	if len(configFilePath) > 0 {
		// compute absolute path based on current working dir
		controllerConfigFile, err := filepath.Abs(configFilePath)
		if err != nil {
			return fmt.Errorf("failed to load config file %s, error %v", configFilePath, err)
		}

		loader, err := configfile.NewConfigurationFSLoader(nil, controllerConfigFile)
		if err != nil {
			return fmt.Errorf("failed to load config file %s, error %v", configFilePath, err)
		}

		controllerConfigFromFile := controllerconfigfile.New()
		if err := loader.Load(controllerConfigFromFile); err != nil {
			return fmt.Errorf("failed to load config file %s, error %v", configFilePath, err)
		}

		controllerConfigFromFile.Config.DeepCopyInto(cfg)

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
