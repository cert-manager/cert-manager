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

package completion

import (
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/kubectl/pkg/cmd/util"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/build"
)

func newCmdCompletionPowerShell(ioStreams genericclioptions.IOStreams) *cobra.Command {
	return &cobra.Command{
		Use:   "powershell",
		Short: "Generate cert-manager CLI scripts for a PowerShell shell",
		Long: build.WithTemplate(`To load completions:
  PS> {{.BuildName}} completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> {{.BuildName}} completion powershell > {{.BuildName}}.ps1
  # and source this file from your PowerShell profile.
`),
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			util.CheckErr(cmd.Root().GenPowerShellCompletion(ioStreams.Out))
		},
	}
}
