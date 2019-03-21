/*
Copyright 2019 The Jetstack cert-manager contributors.

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
	"os"

	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/jetstack/cert-manager/pkg/logs"
)

func main() {
	logs.InitLogs(flag.CommandLine)
	defer logs.FlushLogs()
	ctrl.SetLogger(logs.Log)

	stopCh := ctrl.SetupSignalHandler()
	cmd := NewCommandStartInjectorController(os.Stdout, os.Stderr, stopCh)
	cmd.Flags().AddGoFlagSet(flag.CommandLine)

	flag.CommandLine.Parse([]string{})
	if err := cmd.Execute(); err != nil {
		klog.Fatal(err)
	}
}
