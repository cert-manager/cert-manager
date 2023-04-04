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

	"github.com/cert-manager/cert-manager/cmctl-binary/pkg/approve"
	"github.com/cert-manager/cert-manager/cmctl-binary/pkg/check"
	"github.com/cert-manager/cert-manager/cmctl-binary/pkg/completion"
	"github.com/cert-manager/cert-manager/cmctl-binary/pkg/convert"
	"github.com/cert-manager/cert-manager/cmctl-binary/pkg/create"
	"github.com/cert-manager/cert-manager/cmctl-binary/pkg/deny"
	"github.com/cert-manager/cert-manager/cmctl-binary/pkg/experimental"
	"github.com/cert-manager/cert-manager/cmctl-binary/pkg/inspect"
	"github.com/cert-manager/cert-manager/cmctl-binary/pkg/renew"
	"github.com/cert-manager/cert-manager/cmctl-binary/pkg/status"
	"github.com/cert-manager/cert-manager/cmctl-binary/pkg/upgrade"
	"github.com/cert-manager/cert-manager/cmctl-binary/pkg/version"
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
