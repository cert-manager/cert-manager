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
	"flag"

	"os"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/cert-manager/cert-manager/cmd/cainjector/app"
	"github.com/cert-manager/cert-manager/cmd/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

func main() {
	// Set up signal handlers and a cancellable context which gets cancelled on
	// when either SIGINT or SIGTERM are received.
	stopCh, exit := util.SetupExitHandler(util.GracefulShutdown)
	defer exit() // This function might call os.Exit, so defer last

	logf.InitLogs(flag.CommandLine)
	defer logf.FlushLogs()
	ctrl.SetLogger(logf.Log)

	ctx := util.ContextWithStopCh(context.Background(), stopCh)

	cmd := app.NewCommandStartInjectorController(ctx, os.Stdout, os.Stderr)
	cmd.Flags().AddGoFlagSet(flag.CommandLine)

	flag.CommandLine.Parse([]string{})
	if err := cmd.Execute(); err != nil {
		cmd.PrintErrln(err)
		util.SetExitCode(err)
	}
}
