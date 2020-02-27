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
	goflag "flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/pflag"
	"k8s.io/klog"
	"k8s.io/klog/klogr"

	"github.com/jetstack/cert-manager/cmd/webhook/app"
	"github.com/jetstack/cert-manager/cmd/webhook/app/options"
)

func main() {
	gofs := &goflag.FlagSet{}
	klog.InitFlags(gofs)
	pflag.CommandLine.AddGoFlagSet(gofs)
	opts := &options.WebhookOptions{}
	opts.AddFlags(pflag.CommandLine)
	pflag.Parse()

	log := klogr.New()
	stopCh := setupSignalHandler()

	if err := app.RunServer(log, *opts, stopCh); err != nil {
		log.Error(err, "error running server")
		os.Exit(1)
	}
}

var shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}
var onlyOneSignalHandler = make(chan struct{})

// setupSignalHandler registered for SIGTERM and SIGINT. A stop channel is returned
// which is closed on one of these signals. If a second signal is caught, the program
// is terminated with exit code 1.
func setupSignalHandler() (stopCh <-chan struct{}) {
	close(onlyOneSignalHandler) // panics when called twice

	stop := make(chan struct{})
	c := make(chan os.Signal, 2)
	signal.Notify(c, shutdownSignals...)
	go func() {
		<-c
		close(stop)
		<-c
		os.Exit(1) // second signal. Exit directly.
	}()

	return stop
}
