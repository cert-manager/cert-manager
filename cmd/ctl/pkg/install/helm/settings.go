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

package helm

import (
	"context"
	"fmt"
	"os"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/factory"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
)

const defaultCertManagerNamespace = "cert-manager"
const debugLogLevel = 3

type NormalisedEnvSettings struct {
	logger              logr.Logger
	EnvSettings         *cli.EnvSettings
	ActionConfiguration *action.Configuration
	Factory             *factory.Factory
}

func NewNormalisedEnvSettings() *NormalisedEnvSettings {
	return &NormalisedEnvSettings{
		EnvSettings:         cli.New(),
		ActionConfiguration: &action.Configuration{},
	}
}

func (n *NormalisedEnvSettings) Namespace() string {
	return n.Factory.Namespace
}

func (n *NormalisedEnvSettings) Setup(ctx context.Context, cmd *cobra.Command) {
	log := logf.FromContext(ctx)
	n.logger = log

	n.Factory = factory.New(ctx, cmd)
	n.setupEnvSettings(ctx, cmd)

	{
		// Add a PreRunE hook to initialise the action configuration.
		existingPreRunE := cmd.PreRunE
		cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
			if existingPreRunE != nil {
				if err := existingPreRunE(cmd, args); err != nil {
					return err
				}
			}

			return n.InitActionConfiguration()
		}
	}

	// Fix the default namespace to be cert-manager
	cmd.Flag("namespace").DefValue = defaultCertManagerNamespace
	cmd.Flag("namespace").Value.Set(defaultCertManagerNamespace)
}

func (n *NormalisedEnvSettings) setupEnvSettings(ctx context.Context, cmd *cobra.Command) {
	{
		// Create a tempoary flag set to add the EnvSettings flags to, this
		// can then be iterated over to copy the flags we want to the command
		var tmpFlagSet pflag.FlagSet
		n.EnvSettings.AddFlags(&tmpFlagSet)

		tmpFlagSet.VisitAll(func(f *pflag.Flag) {
			switch f.Name {
			case "registry-config", "repository-config", "repository-cache":
				cmd.Flags().AddFlag(f)
			}
		})
	}

	{
		// Add a PreRunE hook to set the debug value to true if the log level is
		// >= 3.
		existingPreRunE := cmd.PreRunE
		cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
			if n.logger.V(debugLogLevel).Enabled() {
				n.EnvSettings.Debug = true
			}

			if existingPreRunE != nil {
				return existingPreRunE(cmd, args)
			}
			return nil
		}
	}
}

func (n *NormalisedEnvSettings) InitActionConfiguration() error {
	return n.ActionConfiguration.Init(
		n.Factory.RESTClientGetter,
		n.Factory.Namespace,
		os.Getenv("HELM_DRIVER"),
		func(format string, v ...interface{}) {
			n.logger.Info(fmt.Sprintf(format, v...))
		},
	)
}
