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

	"github.com/cert-manager/cert-manager/acmesolver-binary/app"
	"github.com/cert-manager/cert-manager/internal/cmd/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// acmesolver solves ACME http-01 challenges. This is intended to run as a pod
// in the target kubernetes cluster in order to solve challenges for
// cert-manager.

func main() {
	ctx, exit := util.SetupExitHandler(context.Background(), util.GracefulShutdown)
	defer exit() // This function might call os.Exit, so defer last

	logf.InitLogs()
	defer logf.FlushLogs()
	ctx = logf.NewContext(ctx, logf.Log, "acmesolver")

	cmd := app.NewACMESolverCommand(ctx)

	if err := cmd.ExecuteContext(ctx); err != nil {
		logf.Log.Error(err, "error executing command")
		util.SetExitCode(err)
	}
}
