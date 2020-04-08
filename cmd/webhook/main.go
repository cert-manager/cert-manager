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
	goflag "flag"
	"os"

	"github.com/spf13/pflag"
	"k8s.io/klog"
	"k8s.io/klog/klogr"

	"github.com/jetstack/cert-manager/cmd/webhook/app"
	"github.com/jetstack/cert-manager/cmd/webhook/app/options"
	"github.com/jetstack/cert-manager/pkg/util/cmd"
)

func main() {
	gofs := &goflag.FlagSet{}
	klog.InitFlags(gofs)
	pflag.CommandLine.AddGoFlagSet(gofs)
	opts := &options.WebhookOptions{}
	opts.AddFlags(pflag.CommandLine)
	pflag.Parse()

	log := klogr.New()
	stopCh := cmd.SetupSignalHandler()

	if err := app.RunServer(log, *opts, stopCh); err != nil {
		log.Error(err, "error running server")
		os.Exit(1)
	}
}
