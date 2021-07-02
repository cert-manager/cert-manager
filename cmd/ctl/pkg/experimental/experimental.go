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

package experimental

import (
	"context"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	"github.com/jetstack/cert-manager/cmd/ctl/pkg/create"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/create/certificatesigningrequest"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/install"
)

func NewCmdExperimental(ctx context.Context, ioStreams genericclioptions.IOStreams, factory cmdutil.Factory) *cobra.Command {
	cmds := &cobra.Command{
		Use:     "experimental",
		Aliases: []string{"x"},
		Short:   "Interact with experimental features",
		Long:    "Interact with experimental features",
	}

	create := create.NewCmdCreateBare()
	create.AddCommand(certificatesigningrequest.NewCmdCreateCSR(ctx, ioStreams, factory))
	cmds.AddCommand(create)
	cmds.AddCommand(install.NewCmdInstall(ctx, ioStreams, factory))

	return cmds
}
