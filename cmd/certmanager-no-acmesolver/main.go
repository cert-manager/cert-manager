package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	cainjectorapp "github.com/cert-manager/cert-manager/cainjector-binary/app"
	controllerapp "github.com/cert-manager/cert-manager/controller-binary/app"
	"github.com/cert-manager/cert-manager/internal/cmd/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/startupapicheck-binary/pkg/check"
	webhookapp "github.com/cert-manager/cert-manager/webhook-binary/app"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/component-base/logs"
	ctrl "sigs.k8s.io/controller-runtime"
)

func main() {
	ctx, exit := util.SetupExitHandler(context.Background(), util.GracefulShutdown)
	defer exit() // This function might call os.Exit, so defer last

	logf.InitLogs()
	defer logf.FlushLogs()

	if len(os.Args) == 1 {
		fmt.Fprintln(os.Stderr, "No command provided")
		return
	}

	switch strings.ToLower(os.Args[1]) {
	case "controller":
		ctx = logf.NewContext(ctx, logf.Log, "controller")
		cmd := controllerapp.NewServerCommand(ctx)
		cmd.Flags().AddGoFlagSet(flag.CommandLine)

		if err := cmd.ExecuteContext(ctx); err != nil {
			logf.Log.Error(err, "error executing command")
			util.SetExitCode(err)
		}

	case "cainjector":
		ctrl.SetLogger(logf.Log)
		ctx = logf.NewContext(ctx, logf.Log)
		cmd := cainjectorapp.NewCAInjectorCommand(ctx)

		if err := cmd.ExecuteContext(ctx); err != nil {
			logf.Log.Error(err, "error executing command")
			util.SetExitCode(err)
		}

	case "startupapicheck":
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

	case "webhook":
		ctrl.SetLogger(logf.Log)
		ctx = logf.NewContext(ctx, logf.Log, "webhook")

		cmd := webhookapp.NewServerCommand(ctx)

		if err := cmd.ExecuteContext(ctx); err != nil {
			logf.Log.Error(err, "error executing command")
			util.SetExitCode(err)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
	}
}
