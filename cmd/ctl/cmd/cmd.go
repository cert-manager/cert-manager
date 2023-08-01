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

package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/component-base/logs"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/build"
	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/build/commands"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

func NewCertManagerCtlCommand(ctx context.Context, in io.Reader, out, err io.Writer) *cobra.Command {
	ctx = logf.NewContext(ctx, logf.Log)

	logOptions := logs.NewOptions()

	cmds := &cobra.Command{
		Use:   build.Name(),
		Short: "cert-manager CLI tool to manage and configure cert-manager resources",
		Long: build.WithTemplate(`
{{.BuildName}} is a CLI tool manage and configure cert-manager resources for Kubernetes`),
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return logf.ValidateAndApply(logOptions)
		},
		SilenceErrors: true, // Errors are already logged when calling cmd.Execute()
	}
	cmds.SetUsageTemplate(usageTemplate())

	{
		var logFlags pflag.FlagSet
		logf.AddFlagsNonDeprecated(logOptions, &logFlags)

		logFlags.VisitAll(func(f *pflag.Flag) {
			switch f.Name {
			case "v":
				// "cmctl check api" already had a "v" flag that did not require any value, for
				// backwards compatibility we allow the "v" logging flag to be set without a value
				// and default to "2" (which will result in the same behaviour as before).
				f.NoOptDefVal = "2"
				cmds.PersistentFlags().AddFlag(f)
			default:
				cmds.PersistentFlags().AddFlag(f)
			}
		})
	}

	ioStreams := genericclioptions.IOStreams{In: in, Out: out, ErrOut: err}
	for _, registerCmd := range commands.Commands() {
		cmds.AddCommand(registerCmd(ctx, ioStreams))
	}

	return cmds
}

func usageTemplate() string {
	return fmt.Sprintf(`Usage:{{if .Runnable}} %s {{end}}{{if .HasAvailableSubCommands}} %s [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "%s [command] --help" for more information about a command.{{end}}
`, build.Name(), build.Name(), build.Name())
}
