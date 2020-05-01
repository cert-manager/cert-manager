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

package cmd

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	// Load all auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/klog"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	"github.com/jetstack/cert-manager/cmd/ctl/pkg/convert"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/renew"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/version"
)

func NewCertManagerCtlCommand(in io.Reader, out, err io.Writer, stopCh <-chan struct{}) *cobra.Command {
	cmds := &cobra.Command{
		Use:   "cert-manager",
		Short: "cert-manager CLI tool to manage and configure cert-manager resources",
		Long: `
kubectl cert-manager is a CLI tool manage and configure cert-manager resources for Kubernetes`,
		Run: runHelp,
	}

	kubeConfigFlags := genericclioptions.NewConfigFlags(true)
	kubeConfigFlags.AddFlags(cmds.PersistentFlags())
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(kubeConfigFlags)
	matchVersionKubeConfigFlags.AddFlags(cmds.PersistentFlags())
	factory := cmdutil.NewFactory(matchVersionKubeConfigFlags)

	cmds.Flags().AddGoFlagSet(flag.CommandLine)
	flag.CommandLine.Parse([]string{})
	fakefs := flag.NewFlagSet("fake", flag.ExitOnError)
	klog.InitFlags(fakefs)
	if err := fakefs.Parse([]string{"-logtostderr=false"}); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	ioStreams := genericclioptions.IOStreams{In: in, Out: out, ErrOut: err}
	cmds.AddCommand(version.NewCmdVersion(ioStreams))
	cmds.AddCommand(convert.NewCmdConvert(ioStreams))
	cmds.AddCommand(renew.NewCmdRenew(ioStreams, factory))

	return cmds
}

func runHelp(cmd *cobra.Command, args []string) {
	cmd.Help()
}
