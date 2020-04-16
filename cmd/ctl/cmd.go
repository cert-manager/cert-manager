/*
Copyright 2020 The Jetstack cert-manager contributors.

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
	"io"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	"github.com/jetstack/cert-manager/cmd/ctl/pkg/renew"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/version"
)

func NewCertManagerCtlCommand(in io.Reader, out, err io.Writer, stopCh <-chan struct{}) *cobra.Command {
	cmds := &cobra.Command{
		Use:   "cert-manager-ctl",
		Short: "cert-manager CLI tool to manage and configure cert-manager resources",
		Long: `
cert-manager-ctl is a CLI tool manage and configure cert-manager resources for Kubernetes`,
		Run: runHelp,
	}

	kubeConfigFlags := genericclioptions.NewConfigFlags(true).WithDeprecatedPasswordFlag()
	kubeConfigFlags.AddFlags(cmds.PersistentFlags())
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(kubeConfigFlags)
	matchVersionKubeConfigFlags.AddFlags(cmds.PersistentFlags())
	factory := cmdutil.NewFactory(matchVersionKubeConfigFlags)

	ioStreams := genericclioptions.IOStreams{In: in, Out: out, ErrOut: err}
	cmds.AddCommand(version.NewCmdVersion(ioStreams))
	cmds.AddCommand(renew.NewCmdRenew(ioStreams, factory))

	return cmds
}

func runHelp(cmd *cobra.Command, args []string) {
	cmd.Help()
}
