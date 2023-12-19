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
	"strconv"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/factory"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"helm.sh/helm/v3/pkg/cli"
)

const defaultCertManagerNamespace = "cert-manager"
const debugLogLevel = 3

type NormalisedEnvSettings struct {
	EnvSettings *cli.EnvSettings
	Factory     *factory.Factory
}

func NewNormalisedEnvSettings() *NormalisedEnvSettings {
	return &NormalisedEnvSettings{
		EnvSettings: cli.New(),
	}
}

func (n *NormalisedEnvSettings) Namespace() string {
	return n.Factory.Namespace
}

func (n *NormalisedEnvSettings) Setup(ctx context.Context, cmd *cobra.Command) {
	n.Factory = factory.New(ctx, cmd)
	n.addEnvSettingsFlags(cmd)

	// Fix the default namespace to be cert-manager
	cmd.Flag("namespace").DefValue = defaultCertManagerNamespace
	cmd.Flag("namespace").Value.Set(defaultCertManagerNamespace)
}

func (n *NormalisedEnvSettings) addEnvSettingsFlags(cmd *cobra.Command) {
	fs := cmd.Flags()

	// Create a tempoary flag set to add the EnvSettings flags to, this
	// can then be iterated over to copy the flags we want to the command
	var tmpFlagSet pflag.FlagSet
	n.EnvSettings.AddFlags(&tmpFlagSet)

	tmpFlagSet.VisitAll(func(f *pflag.Flag) {
		switch f.Name {
		case "debug":
			// Setup a PreRun to set the helm debug flag. Catch the
			// existing PreRun Debug command if one was defined, and execute
			// it second.
			existingPreRun := cmd.PreRun
			cmd.PreRun = func(cmd *cobra.Command, args []string) {
				if isLogLevelDebug(cmd) {
					f.Value.Set("true")
				}

				if existingPreRun != nil {
					existingPreRun(cmd, args)
				}
			}
		case "registry-config", "repository-config", "repository-cache":
			fs.AddFlag(f)
		}
	})
}

func isLogLevelDebug(cmd *cobra.Command) bool {
	flagValue := cmd.Flag("v").Value.String()
	logLevel, _ := strconv.Atoi(flagValue)
	return logLevel >= debugLogLevel
}
