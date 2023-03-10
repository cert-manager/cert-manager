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
	"github.com/spf13/pflag"
	cliflag "k8s.io/component-base/cli/flag"

	"github.com/cert-manager/cert-manager/controller-binary/app/options"
	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
	cmdutil "github.com/cert-manager/cert-manager/internal/cmd/util"

	_ "github.com/cert-manager/cert-manager/pkg/controller/acmechallenges"
	_ "github.com/cert-manager/cert-manager/pkg/controller/acmeorders"
	_ "github.com/cert-manager/cert-manager/pkg/controller/certificate-shim/gateways"
	_ "github.com/cert-manager/cert-manager/pkg/controller/certificate-shim/ingresses"
	_ "github.com/cert-manager/cert-manager/pkg/controller/certificates/trigger"
	_ "github.com/cert-manager/cert-manager/pkg/controller/clusterissuers"
	controllerconfigfile "github.com/cert-manager/cert-manager/pkg/controller/configfile"
	_ "github.com/cert-manager/cert-manager/pkg/controller/issuers"
	_ "github.com/cert-manager/cert-manager/pkg/issuer/acme"
	_ "github.com/cert-manager/cert-manager/pkg/issuer/ca"
	_ "github.com/cert-manager/cert-manager/pkg/issuer/selfsigned"
	_ "github.com/cert-manager/cert-manager/pkg/issuer/vault"
	_ "github.com/cert-manager/cert-manager/pkg/issuer/venafi"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/pkg/util/configfile"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

const componentController = "controller"

func NewServerCommand(stopCh <-chan struct{}) *cobra.Command {
	ctx := cmdutil.ContextWithStopCh(context.Background(), stopCh)
	log := logf.Log

	ctx = logf.NewContext(ctx, log, componentController)

	cleanFlagSet := pflag.NewFlagSet(componentController, pflag.ContinueOnError)
	// Replaces all instances of `_` in flag names with `-`
	cleanFlagSet.SetNormalizeFunc(cliflag.WordSepNormalizeFunc)
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
		// The controller has special flag parsing requirements to handle precedence of providing
		// configuration via versioned configuration files and flag values.
		// Setting DisableFlagParsing=true prevents Cobra from interfering with flag parsing
		// at all, and instead we handle it all in the RunE below.
		DisableFlagParsing: true,
		Run: func(cmd *cobra.Command, args []string) {
			// initial flag parse, since we disable cobra's flag parsing
			if err := cleanFlagSet.Parse(args); err != nil {
				log.Error(err, "Failed to parse controller flag")
				cmd.Usage()
				os.Exit(1)
			}

			// check if there are non-flag arguments in the command line
			cmds := cleanFlagSet.Args()
			if len(cmds) > 0 {
				log.Error(nil, "Unknown command", "command", cmds[0])
				cmd.Usage()
				os.Exit(1)
			}

			// short-circuit on help
			help, err := cleanFlagSet.GetBool("help")
			if err != nil {
				log.Info(`"help" flag is non-bool, programmer error, please correct`)
				os.Exit(1)
			}
			if help {
				cmd.Help()
				return
			}

			// set feature gates from initial flags-based config
			if err := utilfeature.DefaultMutableFeatureGate.SetFromMap(controllerConfig.FeatureGates); err != nil {
				log.Error(err, "Failed to set feature gates from initial flags-based config")
				os.Exit(1)
			}

			if err := options.ValidateControllerFlags(controllerFlags); err != nil {
				log.Error(err, "Failed to validate controller flags")
				os.Exit(1)
			}

			if configFile := controllerFlags.Config; len(configFile) > 0 {
				controllerConfig, err = loadConfigFile(configFile)
				if err != nil {
					log.Error(err, "Failed to load controller config file", "path", configFile)
					os.Exit(1)
				}

				if err := controllerConfigFlagPrecedence(controllerConfig, args); err != nil {
					log.Error(err, "Failed to merge flags with config file values")
					os.Exit(1)
				}
				// update feature gates based on new config
				if err := utilfeature.DefaultMutableFeatureGate.SetFromMap(controllerConfig.FeatureGates); err != nil {
					log.Error(err, "Failed to set feature gates from config file")
					os.Exit(1)
				}
			}

			// Start the controller
			if err := Run(controllerConfig, stopCh); err != nil {
				log.Error(err, "Failed to run the controller")
				os.Exit(1)
			}
		},
	}

	controllerFlags.AddFlags(cleanFlagSet)
	options.AddConfigFlags(cleanFlagSet, controllerConfig)

	cleanFlagSet.BoolP("help", "h", false, fmt.Sprintf("help for %s", cmd.Name()))

	// ugly, but necessary, because Cobra's default UsageFunc and HelpFunc pollute the flagset with global flags
	const usageFmt = "Usage:\n  %s\n\nFlags:\n%s"
	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine(), cleanFlagSet.FlagUsagesWrapped(2))
		return nil
	})
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine(), cleanFlagSet.FlagUsagesWrapped(2))
	})

	return cmd
}

// newFakeFlagSet constructs a pflag.FlagSet with the same flags as fs, but where
// all values have noop Set implementations
func newFakeFlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("", pflag.ExitOnError)

	// set the normalize func, similar to k8s.io/component-base/cli//flags.go:InitFlags
	fs.SetNormalizeFunc(cliflag.WordSepNormalizeFunc)

	return fs
}

// controllerConfigFlagPrecedence re-parses flags over the ControllerConfiguration object.
// We must enforce flag precedence by re-parsing the command line into the new object.
// This is necessary to preserve backwards-compatibility across binary upgrades.
// See issue #56171 for more details.
func controllerConfigFlagPrecedence(cfg *config.ControllerConfiguration, args []string) error {
	// We use a throwaway controllerFlags and a fake global flagset to avoid double-parses,
	// as some Set implementations accumulate values from multiple flag invocations.
	fs := newFakeFlagSet()
	// register throwaway KubeletFlags
	options.NewControllerFlags().AddFlags(fs)
	// register new ControllerConfiguration
	options.AddConfigFlags(fs, cfg)
	// re-parse flags
	if err := fs.Parse(args); err != nil {
		return err
	}
	return nil
}

func loadConfigFile(name string) (*config.ControllerConfiguration, error) {
	const errFmt = "failed to load controller config file %s, error %v"
	// compute absolute path based on current working dir
	controllerConfigFile, err := filepath.Abs(name)
	if err != nil {
		return nil, fmt.Errorf(errFmt, name, err)
	}
	controllerConfig := controllerconfigfile.New()
	loader, err := configfile.NewConfigurationFSLoader(nil, controllerConfigFile)
	if err != nil {
		return nil, fmt.Errorf(errFmt, name, err)
	}
	if err := loader.Load(controllerConfig); err != nil {
		return nil, fmt.Errorf(errFmt, name, err)
	}

	return controllerConfig.Config, nil
}
