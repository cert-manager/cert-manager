/*
Copyright 2023 The cert-manager Authors.

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

package main

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/component-base/logs"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/cert-manager/cert-manager/internal/cmd/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/startupapicheck-binary/pkg/check"
)

func main() {
	ctx, exit := util.SetupExitHandler(context.Background(), util.AlwaysErrCode)
	defer exit() // This function might call os.Exit, so defer last

	logf.InitLogs()
	defer logf.FlushLogs()
	ctrl.SetLogger(logf.Log)
	ctx = logf.NewContext(ctx, logf.Log, "startupapicheck")

	logOptions := logs.NewOptions()

	cmd := &cobra.Command{
		Use:   "startupapicheck",
		Short: "Check that cert-manager started successfully",
		Long:  "Check that cert-manager started successfully",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return logf.ValidateAndApply(logOptions)
		},

		SilenceErrors: true, // Errors are already logged when calling cmd.Execute()
		SilenceUsage:  true, // Don't print usage on every error
	}

	{
		var logFlags pflag.FlagSet
		logf.AddFlagsNonDeprecated(logOptions, &logFlags)

		logFlags.VisitAll(func(f *pflag.Flag) {
			switch f.Name {
			case "v":
				// "cmctl check api" already had a "v" flag that did not require any value; to maintain compatibility with cmctl
				// and backwards compatibility we allow the "v" logging flag to be set without a value
				// and default to "2" (which will result in the same behaviour as before).
				f.NoOptDefVal = "2"
				cmd.PersistentFlags().AddFlag(f)
			default:
				cmd.PersistentFlags().AddFlag(f)
			}
		})
	}

	cmd.AddCommand(check.NewCmdCheck(ctx))

	if err := cmd.ExecuteContext(ctx); err != nil {
		logf.Log.Error(err, "error executing command")
		util.SetExitCode(err)
	}
}
