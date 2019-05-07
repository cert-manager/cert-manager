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
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	flag "github.com/spf13/pflag"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/jetstack/cert-manager/hack/release/pkg/bazel"
	"github.com/jetstack/cert-manager/hack/release/pkg/build/chart"
	"github.com/jetstack/cert-manager/hack/release/pkg/build/images"
	"github.com/jetstack/cert-manager/hack/release/pkg/build/manifests"
	"github.com/jetstack/cert-manager/hack/release/pkg/flags"
	"github.com/jetstack/cert-manager/hack/release/pkg/helm"
	logf "github.com/jetstack/cert-manager/hack/release/pkg/log"
)

var (
	buildAll       bool
	buildImages    bool
	buildChart     bool
	buildManifests bool
	publish        bool

	log = logf.Log
)

type flagSource interface {
	AddFlags(*flag.FlagSet)
	Validate() []error
	Complete() error
}

type plugin interface {
	Build(context.Context) error
	InitPublish() []error
	Publish(context.Context) error
}

var flagSources = []flagSource{
	flags.Default,
	bazel.Default,
	helm.Default,
}

var plugins = map[*bool]plugin{
	&buildImages:    images.Default,
	&buildChart:     chart.Default,
	&buildManifests: manifests.Default,
}

// AddFlags adds the flags for the release binary to the given flagset.
// It returns a validation function that can be called to validate all the user
// specified flags.
func AddFlags(fs *flag.FlagSet) func() error {
	fs.BoolVar(&buildAll, "all", false, "build all release targets")
	fs.BoolVar(&buildImages, "images", false, "build docker image release targets")
	fs.BoolVar(&buildChart, "chart", false, "build helm chart release targets")
	fs.BoolVar(&buildManifests, "manifests", false, "build static deployment manifest targets")
	fs.BoolVar(&publish, "publish", false, "if true, artifacts will be published")

	sources := append([]flagSource{}, flagSources...)
	for _, p := range plugins {
		if flagSrc, ok := p.(flagSource); ok {
			sources = append(sources, flagSrc)
		}
	}

	for _, flagSrc := range sources {
		flagSrc.AddFlags(fs)
	}

	return func() error {
		var errs []error

		// validate flagSource flags
		for _, flagSrc := range flagSources {
			errs = append(errs, flagSrc.Validate()...)
		}
		// only validate flags for plugins that are enabled
		for shouldPtr, p := range plugins {
			if buildAll || *shouldPtr {
				if p, ok := p.(flagSource); ok {
					errs = append(errs, p.Validate()...)
				}
			}
		}

		if len(errs) > 0 {
			return utilerrors.NewAggregate(errs)
		}

		// Complete flagSource flags
		for _, flagSrc := range flagSources {
			errs = append(errs, flagSrc.Complete())
		}
		// only Complete flags for plugins that are enabled
		for shouldPtr, p := range plugins {
			if buildAll || *shouldPtr {
				if p, ok := p.(flagSource); ok {
					errs = append(errs, p.Complete())
				}
			}
		}

		return utilerrors.NewAggregate(errs)
	}
}

func main() {
	fs := &flag.FlagSet{}
	logf.InitLogs(fs)

	validate := AddFlags(fs)
	fs.Parse(os.Args[1:])

	if err := validate(); err != nil {
		log.Error(err, "error parsing flags")
		os.Exit(1)
	}

	stopCh := SetupSignalHandler()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()
		<-stopCh
	}()

	log.Info("running all build targets")
	// only run enabled plugins
	for shouldPtr, p := range plugins {
		if buildAll || *shouldPtr {
			err := p.Build(ctx)
			if err != nil {
				log.Error(err, "error running build job")
				os.Exit(2)
			}
		}
	}

	var errs []error
	for shouldPtr, p := range plugins {
		if publish && (buildAll || *shouldPtr) {
			log.Info("running InitPublish")
			errs = append(errs, p.InitPublish()...)
		}
	}

	if len(errs) > 0 {
		log.Error(fmt.Errorf("%v", errs), "error validating publishing configuration")
		os.Exit(3)
	}

	// only publish enabled plugins
	for shouldPtr, p := range plugins {
		if publish && (buildAll || *shouldPtr) {
			log.Info("running Publish")
			err := p.Publish(ctx)
			if err != nil {
				log.Error(err, "error running publish job")
				os.Exit(4)
			}
		}
	}
}

var shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}
var onlyOneSignalHandler = make(chan struct{})

// SetupSignalHandler registered for SIGTERM and SIGINT. A stop channel is returned
// which is closed on one of these signals. If a second signal is caught, the program
// is terminated with exit code 1.
func SetupSignalHandler() (stopCh <-chan struct{}) {
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
