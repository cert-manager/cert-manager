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

func newCmdCompletionZSH(ioStreams genericclioptions.IOStreams) *cobra.Command {
	return &cobra.Command{
		Use:   "zsh",
		Short: "Generation cert-manager CLI scripts for a ZSH shell",
		Long: build.WithTemplate(`To load completions:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ {{.BuildName}} completion zsh > "${fpath[1]}/_{{.BuildName}}"
  # You will need to start a new shell for this setup to take effect.
`),
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			util.CheckErr(cmd.Root().GenZshCompletion(ioStreams.Out))
		},
	}
}
