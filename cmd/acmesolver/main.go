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
	"fmt"
	"os"

	"github.com/cert-manager/cert-manager/cmd/acmesolver/app"
	utilcmd "github.com/cert-manager/cert-manager/pkg/util/cmd"
)

// acmesolver solves ACME http-01 challenges. This is intended to run as a pod
// in the target kubernetes cluster in order to solve challenges for
// cert-manager.

func main() {
	stopCh := utilcmd.SetupSignalHandler()
	cmd := app.NewACMESolverCommand(stopCh)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
}
