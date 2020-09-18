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
	"context"
	"fmt"
	"io"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/sync/errgroup"
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
func NewCommandStartInjectorController(ctx context.Context, out, errOut io.Writer) *cobra.Command {
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
		RunE: func(cmd *cobra.Command, args []string) error {
			o.log = logf.Log.WithName("ca-injector")

			logf.V(logf.InfoLevel).InfoS("starting", "version", util.AppVersion, "revision", util.AppGitCommit)
			return o.RunInjectorController(ctx)
		},
	}

	flags := cmd.Flags()
	o.AddFlags(flags)

	return cmd
}

func (o InjectorControllerOptions) RunInjectorController(ctx context.Context) error {
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  api.Scheme,
		Namespace:               o.Namespace,
		LeaderElection:          o.LeaderElect,
		LeaderElectionNamespace: o.LeaderElectionNamespace,
		LeaderElectionID:        "cert-manager-cainjector-leader-election",
		MetricsBindAddress:      "0",
	})
	if err != nil {
		return fmt.Errorf("error creating manager: %v", err)
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() (err error) {
		defer func() {
			o.log.Error(err, "manager goroutine exited")
		}()

		if err = mgr.Start(gctx.Done()); err != nil {
			return fmt.Errorf("error running manager: %v", err)
		}
		return nil
	})

	<-mgr.Elected()

	g.Go(func() (err error) {
		for {
			err = cainjector.RegisterCertificateBased(gctx, mgr)
			if err == nil {
				return
			}
			o.log.Error(err, "Error registering certificate based controllers. Retrying after 5 seconds.")
			select {
			case <-time.After(time.Second * 5):
			case <-gctx.Done():
				return
			}
		}
	})

	g.Go(func() (err error) {
		if err = cainjector.RegisterSecretBased(gctx, mgr); err != nil {
			return fmt.Errorf("error registering secret controller: %v", err)
		}
		return
	})

	return g.Wait()
}
