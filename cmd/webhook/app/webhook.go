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

	cmdutil "github.com/cert-manager/cert-manager/cmd/util"
	"github.com/cert-manager/cert-manager/cmd/webhook/app/options"
	config "github.com/cert-manager/cert-manager/internal/apis/config/webhook"
	cmwebhook "github.com/cert-manager/cert-manager/internal/webhook"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/pkg/webhook/configfile"
)

const componentWebhook = "webhook"

func NewServerCommand(stopCh <-chan struct{}) *cobra.Command {
	ctx := cmdutil.ContextWithStopCh(context.Background(), stopCh)
	log := logf.Log
	ctx = logf.NewContext(ctx, log, componentWebhook)

	cleanFlagSet := pflag.NewFlagSet(componentWebhook, pflag.ContinueOnError)
	// Replaces all instances of `_` in flag names with `-`
	cleanFlagSet.SetNormalizeFunc(cliflag.WordSepNormalizeFunc)
	webhookFlags := options.NewWebhookFlags()
	webhookConfig, err := options.NewWebhookConfiguration()
	if err != nil {
		log.Error(err, "Failed to create new webhook configuration")
		os.Exit(1)
	}

	cmd := &cobra.Command{
		Use:  componentWebhook,
		Long: fmt.Sprintf("Webhook component providing API validation, mutation and conversion functionality for cert-manager (%s) (%s)", util.AppVersion, util.AppGitCommit),
		// The webhook has special flag parsing requirements to handle precedence of providing
		// configuration via versioned configuration files and flag values.
		// Setting DisableFlagParsing=true prevents Cobra from interfering with flag parsing
		// at all, and instead we handle it all in the RunE below.
		DisableFlagParsing: true,
		Run: func(cmd *cobra.Command, args []string) {
			// initial flag parse, since we disable cobra's flag parsing
			if err := cleanFlagSet.Parse(args); err != nil {
				log.Error(err, "Failed to parse webhook flag")
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
			if err := utilfeature.DefaultMutableFeatureGate.SetFromMap(webhookConfig.FeatureGates); err != nil {
				log.Error(err, "Failed to set feature gates from initial flags-based config")
				os.Exit(1)
			}

			if err := options.ValidateWebhookFlags(webhookFlags); err != nil {
				log.Error(err, "Failed to validate webhook flags")
				os.Exit(1)
			}

			if configFile := webhookFlags.Config; len(configFile) > 0 {
				webhookConfig, err = loadConfigFile(configFile)
				if err != nil {
					log.Error(err, "Failed to load webhook config file", "path", configFile)
					os.Exit(1)
				}

				if err := webhookConfigFlagPrecedence(webhookConfig, args); err != nil {
					log.Error(err, "Failed to merge flags with config file values")
					os.Exit(1)
				}
				// update feature gates based on new config
				if err := utilfeature.DefaultMutableFeatureGate.SetFromMap(webhookConfig.FeatureGates); err != nil {
					log.Error(err, "Failed to set feature gates from config file")
					os.Exit(1)
				}
			}

			srv, err := cmwebhook.NewCertManagerWebhookServer(log, *webhookFlags, *webhookConfig)
			if err != nil {
				log.Error(err, "Failed initialising server")
				os.Exit(1)
			}

			if err := srv.Run(ctx); err != nil {
				log.Error(err, "Failed running server")
				os.Exit(1)
			}
		},
	}

	webhookFlags.AddFlags(cleanFlagSet)
	options.AddConfigFlags(cleanFlagSet, webhookConfig)
	options.AddGlobalFlags(cleanFlagSet)

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

// newFlagSetWithGlobals constructs a new pflag.FlagSet with global flags registered
// on it.
func newFlagSetWithGlobals() *pflag.FlagSet {
	fs := pflag.NewFlagSet("", pflag.ExitOnError)
	// set the normalize func, similar to k8s.io/component-base/cli//flags.go:InitFlags
	fs.SetNormalizeFunc(cliflag.WordSepNormalizeFunc)
	// explicitly add flags from libs that register global flags
	options.AddGlobalFlags(fs)
	return fs
}

// newFakeFlagSet constructs a pflag.FlagSet with the same flags as fs, but where
// all values have noop Set implementations
func newFakeFlagSet(fs *pflag.FlagSet) *pflag.FlagSet {
	ret := pflag.NewFlagSet("", pflag.ExitOnError)
	ret.SetNormalizeFunc(fs.GetNormalizeFunc())
	fs.VisitAll(func(f *pflag.Flag) {
		ret.VarP(cliflag.NoOp{}, f.Name, f.Shorthand, f.Usage)
	})
	return ret
}

// webhookConfigFlagPrecedence re-parses flags over the WebhookConfiguration object.
// We must enforce flag precedence by re-parsing the command line into the new object.
// This is necessary to preserve backwards-compatibility across binary upgrades.
// See issue #56171 for more details.
func webhookConfigFlagPrecedence(cfg *config.WebhookConfiguration, args []string) error {
	// We use a throwaway webhookFlags and a fake global flagset to avoid double-parses,
	// as some Set implementations accumulate values from multiple flag invocations.
	fs := newFakeFlagSet(newFlagSetWithGlobals())
	// register throwaway KubeletFlags
	options.NewWebhookFlags().AddFlags(fs)
	// register new WebhookConfiguration
	options.AddConfigFlags(fs, cfg)
	// re-parse flags
	if err := fs.Parse(args); err != nil {
		return err
	}
	return nil
}

func loadConfigFile(name string) (*config.WebhookConfiguration, error) {
	const errFmt = "failed to load webhook config file %s, error %v"
	// compute absolute path based on current working dir
	webhookConfigFile, err := filepath.Abs(name)
	if err != nil {
		return nil, fmt.Errorf(errFmt, name, err)
	}
	loader, err := configfile.NewFSLoader(configfile.NewRealFS(), webhookConfigFile)
	if err != nil {
		return nil, fmt.Errorf(errFmt, name, err)
	}
	cfg, err := loader.Load()
	if err != nil {
		return nil, fmt.Errorf(errFmt, name, err)
	}
	return cfg, nil
}
