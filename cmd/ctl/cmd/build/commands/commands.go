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

package commands

import (
	"context"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/cert-manager/cert-manager/cmd/ctl/cmd/approve"
	"github.com/cert-manager/cert-manager/cmd/ctl/cmd/check"
	"github.com/cert-manager/cert-manager/cmd/ctl/cmd/completion"
	"github.com/cert-manager/cert-manager/cmd/ctl/cmd/convert"
	"github.com/cert-manager/cert-manager/cmd/ctl/cmd/create"
	"github.com/cert-manager/cert-manager/cmd/ctl/cmd/deny"
	"github.com/cert-manager/cert-manager/cmd/ctl/cmd/experimental"
	"github.com/cert-manager/cert-manager/cmd/ctl/cmd/inspect"
	"github.com/cert-manager/cert-manager/cmd/ctl/cmd/renew"
	"github.com/cert-manager/cert-manager/cmd/ctl/cmd/status"
	"github.com/cert-manager/cert-manager/cmd/ctl/cmd/upgrade"
	"github.com/cert-manager/cert-manager/cmd/ctl/cmd/version"
)

// registerCompletion gates whether the completion command is registered.
// Specifically useful when building the CLI as a kubectl plugin which does not
// support completion.
var registerCompletion = "false"

type RegisterCommandFunc func(context.Context, genericclioptions.IOStreams) *cobra.Command

// Commands returns the cobra Commands that should be registered for the CLI
// build.
func Commands() []RegisterCommandFunc {
	cmds := []RegisterCommandFunc{
		version.NewCmdVersion,
		convert.NewCmdConvert,
		create.NewCmdCreate,
		renew.NewCmdRenew,
		status.NewCmdStatus,
		inspect.NewCmdInspect,
		approve.NewCmdApprove,
		deny.NewCmdDeny,
		check.NewCmdCheck,
		upgrade.NewCmdUpgrade,

		// Experimental features
		experimental.NewCmdExperimental,
	}

	if strings.ToLower(registerCompletion) == "true" {
		cmds = append(cmds, completion.NewCmdCompletion)
	}

	return cmds
}
