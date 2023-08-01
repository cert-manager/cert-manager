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

package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	ctlcmd "github.com/cert-manager/cert-manager/cmd/ctl/cmd"
	"github.com/cert-manager/cert-manager/internal/cmd/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

func main() {
	stopCh, exit := util.SetupExitHandler(util.AlwaysErrCode)
	defer exit() // This function might call os.Exit, so defer last

	logf.InitLogs()
	defer logf.FlushLogs()

	// In cmctl, we are using cmdutil.CheckErr, a kubectl utility function that creates human readable
	// error messages from errors. By default, this function will call os.Exit(1) if it receives an error.
	// Instead, we want to do a soft exit, and use SetExitCode to set the correct exit code.
	// Additionally, we make sure to output the final error message to stdout, as we do not want this
	// message to be mixed with other log outputs from the execution of the command.
	// To do this, we need to set a custom error handler.
	cmdutil.BehaviorOnFatal(func(msg string, code int) {
		if len(msg) > 0 {
			// add newline if needed
			if !strings.HasSuffix(msg, "\n") {
				msg += "\n"
			}
			fmt.Fprint(os.Stdout, msg)
		}

		util.SetExitCodeValue(code)
		runtime.Goexit() // Do soft exit (handle all defers, that should set correct exit code)
	})

	ctx := util.ContextWithStopCh(context.Background(), stopCh)
	cmd := ctlcmd.NewCertManagerCtlCommand(ctx, os.Stdin, os.Stdout, os.Stderr)

	if err := cmd.Execute(); err != nil {
		cmdutil.CheckErr(err)
	}
}
