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

	"github.com/jetstack/cert-manager/cmd/ctl/pkg/approve"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/check"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/completion"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/convert"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/create"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/deny"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/experimental"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/inspect"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/renew"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/status"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/version"
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

		// Experimental features
		experimental.NewCmdExperimental,
	}

	if strings.ToLower(registerCompletion) == "true" {
		cmds = append(cmds, completion.NewCmdCompletion)
	}

	return cmds
}
