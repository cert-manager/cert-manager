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

package cmd

import (
	"context"
	"os"
	"runtime"

	"k8s.io/component-base/logs"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/cert-manager/cert-manager/internal/cmd/util"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd/server"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// RunWebhookServer creates and starts a new apiserver that acts as an external
// webhook server for solving DNS challenges using the provided solver
// implementations. This can be used as an entry point by external webhook
// implementations, see
// https://github.com/cert-manager/webhook-example/blob/899c408751425f8d0842b61c0e62fd8035d00316/main.go#L23-L31
func RunWebhookServer(groupName string, hooks ...webhook.Solver) {
	ctx, exit := util.SetupExitHandler(context.Background(), util.GracefulShutdown)
	defer exit() // This function might call os.Exit, so defer last

	logs.InitLogs()
	defer logs.FlushLogs()
	ctrl.SetLogger(logf.Log)
	ctx = logf.NewContext(ctx, logf.Log, "acme-dns-webhook")

	if len(os.Getenv("GOMAXPROCS")) == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	cmd := server.NewCommandStartWebhookServer(ctx, groupName, hooks...)

	if err := cmd.ExecuteContext(ctx); err != nil {
		logf.Log.Error(err, "error executing command")
		util.SetExitCode(err)
	}
}
