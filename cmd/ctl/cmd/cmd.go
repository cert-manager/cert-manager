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
	"io"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	// Load all auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/jetstack/cert-manager/cmd/ctl/pkg/approve"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/convert"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/create"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/deny"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/experimental"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/flags"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/inspect"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/renew"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/status"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/version"
)

func NewCertManagerCtlCommand(ctx context.Context, in io.Reader, out, err io.Writer) *cobra.Command {
	cmds := &cobra.Command{
		Use:   "cert-manager",
		Short: "cert-manager CLI tool to manage and configure cert-manager resources",
		Long: `
kubectl cert-manager is a CLI tool manage and configure cert-manager resources for Kubernetes`,
	}
	cmds.SetUsageTemplate(usageTemplate)

	factory := flags.AddFlags(cmds)

	ioStreams := genericclioptions.IOStreams{In: in, Out: out, ErrOut: err}
	cmds.AddCommand(version.NewCmdVersion(ctx, ioStreams))
	cmds.AddCommand(convert.NewCmdConvert(ctx, ioStreams))
	cmds.AddCommand(create.NewCmdCreate(ctx, ioStreams, factory))
	cmds.AddCommand(renew.NewCmdRenew(ctx, ioStreams, factory))
	cmds.AddCommand(status.NewCmdStatus(ctx, ioStreams, factory))
	cmds.AddCommand(inspect.NewCmdInspect(ctx, ioStreams, factory))
	cmds.AddCommand(approve.NewCmdApprove(ctx, ioStreams, factory))
	cmds.AddCommand(deny.NewCmdDeny(ctx, ioStreams, factory))

	// Experimental features
	cmds.AddCommand(experimental.NewCmdExperimental(ctx, ioStreams, factory))

	return cmds
}

const usageTemplate = `Usage:{{if .Runnable}}
  kubectl {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  kubectl {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

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

Use "kubectl {{.CommandPath}} [command] --help" for more information about a command.{{end}}
`
