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

	ctlcmd "github.com/jetstack/cert-manager/cmd/ctl/cmd"
	"github.com/jetstack/cert-manager/pkg/util"
	utilcmd "github.com/jetstack/cert-manager/pkg/util/cmd"
)

func main() {
	stopCh := utilcmd.SetupSignalHandler()
	ctx := util.ContextWithStopCh(context.Background(), stopCh)
	cmd := ctlcmd.NewCertManagerCtlCommand(ctx, os.Stdin, os.Stdout, os.Stderr)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
}
