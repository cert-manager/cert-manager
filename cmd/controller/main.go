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
	"flag"

	"github.com/cert-manager/cert-manager/controller-binary/app"

	"github.com/cert-manager/cert-manager/internal/cmd/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

func main() {
	stopCh, exit := util.SetupExitHandler(util.GracefulShutdown)
	defer exit() // This function might call os.Exit, so defer last

	logf.InitLogs()
	defer logf.FlushLogs()

	cmd := app.NewServerCommand(stopCh)
	cmd.Flags().AddGoFlagSet(flag.CommandLine)

	if err := cmd.Execute(); err != nil {
		logf.Log.Error(err, "error executing command")
		util.SetExitCode(err)
	}
}
