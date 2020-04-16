/*
Copyright 2020 The Jetstack cert-manager contributors.

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
	"fmt"
	"os"

	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/util/cmd"
)

func main() {
	stopCh := cmd.SetupSignalHandler()
	cmd := NewCertManagerCtlCommand(os.Stdin, os.Stdout, os.Stderr, stopCh)
	cmd.Flags().AddGoFlagSet(flag.CommandLine)
	flag.CommandLine.Parse([]string{})
	fakefs := flag.NewFlagSet("fake", flag.ExitOnError)
	klog.InitFlags(fakefs)
	if err := fakefs.Parse([]string{"-logtostderr=false"}); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
}
