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

package app

import (
	"fmt"
	"io"
	"os"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/jetstack/cert-manager/pkg/api"
	"github.com/jetstack/cert-manager/pkg/controller/cainjector"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util"
)

type InjectorControllerOptions struct {
	Namespace               string
	LeaderElect             bool
	LeaderElectionNamespace string

	StdOut io.Writer
	StdErr io.Writer

	// logger to be used by this controller
	log logr.Logger
}

func (o *InjectorControllerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Namespace, "namespace", "", ""+
		"If set, this limits the scope of cainjector to a single namespace. "+
		"If set, cainjector will not update resources with certificates outside of the "+
		"configured namespace.")
	fs.BoolVar(&o.LeaderElect, "leader-elect", true, ""+
		"If true, cainjector will perform leader election between instances to ensure no more "+
		"than one instance of cainjector operates at a time")
	fs.StringVar(&o.LeaderElectionNamespace, "leader-election-namespace", "", ""+
		"Namespace used to perform leader election (defaults to controller's namespace). "+
		"Only used if leader election is enabled")
}

func NewInjectorControllerOptions(out, errOut io.Writer) *InjectorControllerOptions {
	o := &InjectorControllerOptions{
		StdOut: out,
		StdErr: errOut,
	}

	return o
}

// NewCommandStartInjectorController is a CLI handler for starting cert-manager
func NewCommandStartInjectorController(out, errOut io.Writer, stopCh <-chan struct{}) *cobra.Command {
	o := NewInjectorControllerOptions(out, errOut)

	cmd := &cobra.Command{
		Use:   "ca-injector",
		Short: fmt.Sprintf("CA Injection Controller for Kubernetes (%s) (%s)", util.AppVersion, util.AppGitCommit),
		Long: `
cert-manager CA injector is a Kubernetes addon to automate the injection of CA data into
webhooks and APIServices from cert-manager certificates.

It will ensure that annotated webhooks and API services always have the correct
CA data from the referenced certificates, which can then be used to serve API
servers and webhook servers.`,

		// TODO: Refactor this function from this package
		Run: func(cmd *cobra.Command, args []string) {
			o.log = logf.Log.WithName("ca-injector")

			logf.V(logf.InfoLevel).InfoS("starting", "version", util.AppVersion, "revision", util.AppGitCommit)
			o.RunInjectorController(stopCh)
		},
	}

	flags := cmd.Flags()
	o.AddFlags(flags)

	return cmd
}

func (o InjectorControllerOptions) RunInjectorController(stopCh <-chan struct{}) {
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  api.Scheme,
		Namespace:               o.Namespace,
		LeaderElection:          o.LeaderElect,
		LeaderElectionNamespace: o.LeaderElectionNamespace,
		LeaderElectionID:        "cert-manager-cainjector-leader-election",
		MetricsBindAddress:      "0",
	})

	if err != nil {
		o.log.Error(err, "error creating manager")
		os.Exit(1)
	}

	if err := cainjector.RegisterSecretBased(mgr); err != nil {
		o.log.Error(err, "error registering core-only controllers")
		os.Exit(1)
	}

	if err := cainjector.RegisterCertificateBased(mgr); err != nil {
		o.log.Error(err, "error registering controllers")
		os.Exit(1)
	}

	if err := mgr.Start(stopCh); err != nil {
		o.log.Error(err, "error running manager")
		os.Exit(1)
	}
}
