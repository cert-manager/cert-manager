/*
Copyright 2022 The cert-manager Authors.

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

package upgrade

import (
	"context"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/upgrade/migrateapiversion"
)

func NewCmdUpgrade(ctx context.Context, ioStreams genericclioptions.IOStreams) *cobra.Command {
	cmds := &cobra.Command{
		Use:   "upgrade",
		Short: "Tools that assist in upgrading cert-manager",
		Long:  `Note: this command does NOT actually upgrade cert-manager installations`,
	}

	cmds.AddCommand(migrateapiversion.NewCmdMigrate(ctx, ioStreams))

	return cmds
}
