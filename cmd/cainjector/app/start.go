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

package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/sync/errgroup"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmdutil "github.com/cert-manager/cert-manager/cmd/util"
	"github.com/cert-manager/cert-manager/pkg/api"
	"github.com/cert-manager/cert-manager/pkg/controller/cainjector"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/pkg/util/profiling"
)

// InjectorControllerOptions is a struct having injector controller options values
type InjectorControllerOptions struct {
	Namespace               string
	LeaderElect             bool
	LeaderElectionNamespace string
	LeaseDuration           time.Duration
	RenewDeadline           time.Duration
	RetryPeriod             time.Duration

	StdOut io.Writer
	StdErr io.Writer

	// EnablePprof determines whether Go profiler should be run.
	EnablePprof bool
	// PprofAddr is the address at which Go profiler will be run if enabled.
	// The profiler should never be exposed on a public address.
	PprofAddr string

	// WatchCerts detemines whether cainjector's control loops will watch
	// cert-manager Certificate resources as potential sources of CA data.
	WatchCerts bool

	// logger to be used by this controller
	log logr.Logger
}

// AddFlags adds the various flags for injector controller options
func (o *InjectorControllerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Namespace, "namespace", "", ""+
		"If set, this limits the scope of cainjector to a single namespace. "+
		"If set, cainjector will not update resources with certificates outside of the "+
		"configured namespace.")
	fs.BoolVar(&o.LeaderElect, "leader-elect", cmdutil.DefaultLeaderElect, ""+
		"If true, cainjector will perform leader election between instances to ensure no more "+
		"than one instance of cainjector operates at a time")
	fs.StringVar(&o.LeaderElectionNamespace, "leader-election-namespace", cmdutil.DefaultLeaderElectionNamespace, ""+
		"Namespace used to perform leader election. Only used if leader election is enabled")
	fs.DurationVar(&o.LeaseDuration, "leader-election-lease-duration", cmdutil.DefaultLeaderElectionLeaseDuration, ""+
		"The duration that non-leader candidates will wait after observing a leadership "+
		"renewal until attempting to acquire leadership of a led but unrenewed leader "+
		"slot. This is effectively the maximum duration that a leader can be stopped "+
		"before it is replaced by another candidate. This is only applicable if leader "+
		"election is enabled.")
	fs.DurationVar(&o.RenewDeadline, "leader-election-renew-deadline", cmdutil.DefaultLeaderElectionRenewDeadline, ""+
		"The interval between attempts by the acting master to renew a leadership slot "+
		"before it stops leading. This must be less than or equal to the lease duration. "+
		"This is only applicable if leader election is enabled.")
	fs.DurationVar(&o.RetryPeriod, "leader-election-retry-period", cmdutil.DefaultLeaderElectionRetryPeriod, ""+
		"The duration the clients should wait between attempting acquisition and renewal "+
		"of a leadership. This is only applicable if leader election is enabled.")

	fs.BoolVar(&o.EnablePprof, "enable-profiling", cmdutil.DefaultEnableProfiling, "Enable profiling for cainjector")
	fs.BoolVar(&o.WatchCerts, "watch-certificates", true, "Watch cert-manager.io Certificate resources as potential sources for CA data. Requires cert-manager.io Certificate CRD to be installed. It is not required to watch Certificates if you only use cainjector as cert-manager's internal components and in that case setting this flag to false might slightly reduce memory consumption.")
	fs.StringVar(&o.PprofAddr, "profiler-address", cmdutil.DefaultProfilerAddr, "Address of the Go profiler (pprof) if enabled. This should never be exposed on a public interface.")

	utilfeature.DefaultMutableFeatureGate.AddFlag(fs)
}

// NewInjectorControllerOptions returns a new InjectorControllerOptions
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
		Scheme:                        api.Scheme,
		Namespace:                     o.Namespace,
		LeaderElection:                o.LeaderElect,
		LeaderElectionNamespace:       o.LeaderElectionNamespace,
		LeaderElectionID:              "cert-manager-cainjector-leader-election",
		LeaderElectionReleaseOnCancel: true,
		LeaderElectionResourceLock:    resourcelock.LeasesResourceLock,
		LeaseDuration:                 &o.LeaseDuration,
		RenewDeadline:                 &o.RenewDeadline,
		RetryPeriod:                   &o.RetryPeriod,
		MetricsBindAddress:            "0",
	})
	if err != nil {
		return fmt.Errorf("error creating manager: %v", err)
	}

	g, gctx := errgroup.WithContext(ctx)

	// if a PprofAddr is provided, start the pprof listener
	if o.EnablePprof {
		pprofListener, err := net.Listen("tcp", o.PprofAddr)
		if err != nil {
			return err
		}

		profilerMux := http.NewServeMux()
		// Add pprof endpoints to this mux
		profiling.Install(profilerMux)
		o.log.V(logf.InfoLevel).Info("running go profiler on", "address", o.PprofAddr)
		server := &http.Server{
			Handler: profilerMux,
		}
		g.Go(func() error {
			<-gctx.Done()
			// allow a timeout for graceful shutdown
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := server.Shutdown(ctx); err != nil {
				return err
			}
			return nil
		})
		g.Go(func() error {
			if err := server.Serve(pprofListener); err != http.ErrServerClosed {
				return err
			}
			return nil
		})
	}

	// If cainjector has been configured to watch Certificate CRDs
	// (--watch-certificates=true), poll kubeapiserver for 5 minutes or till
	// certificate CRD is found.
	if o.WatchCerts {
		directClient, err := client.New(mgr.GetConfig(), client.Options{
			Scheme: mgr.GetScheme(),
			Mapper: mgr.GetRESTMapper(),
		})
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}
		err = wait.PollImmediate(time.Second, time.Minute*5, func() (bool, error) {
			certsCRDName := types.NamespacedName{Name: "certificates.cert-manager.io"}
			certsCRD := apiext.CustomResourceDefinition{}
			err := directClient.Get(ctx, certsCRDName, &certsCRD)
			if apierrors.IsNotFound(err) {
				o.log.Info("cainjector has been configured to watch certificates, but certificates.cert-manager.io CRD not found, retrying with a backoff...")
				return false, nil
			} else if err != nil {
				o.log.Error(err, "error checking if certificates.cert-manager.io CRD is installed")
				return false, err
			}
			o.log.V(logf.DebugLevel).Info("certificates.cert-manager.io CRD found")
			return true, nil
		})
		if err != nil {
			o.log.Error(err, "error retrieving certificate.cert-manager.io CRDs")
			return err
		}
	}

	// TODO: make the controllers to be started optional
	err = cainjector.RegisterAllInjectors(gctx, mgr, o.Namespace, o.WatchCerts)
	if err != nil {
		o.log.Error(err, "failed to register controllers", err)
		return err
	}
	if err = mgr.Start(gctx); err != nil {
		return fmt.Errorf("error running manager: %v", err)
	}
	return nil
}
