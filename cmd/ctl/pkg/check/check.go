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

package check

import (
	"context"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/check/api"
)

// NewCmdCheck returns a cobra command for checking cert-manager components.
func NewCmdCheck(ctx context.Context, ioStreams genericclioptions.IOStreams) *cobra.Command {
	cmds := NewCmdCreateBare()
	cmds.AddCommand(api.NewCmdCheckApi(ctx, ioStreams))

	return cmds
}

// NewCmdCreateBare returns bare cobra command for checking cert-manager components.
func NewCmdCreateBare() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Check cert-manager components",
		Long:  `Check cert-manager components`,
	}
}
