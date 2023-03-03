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
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/api/resource"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"

	"github.com/cert-manager/cert-manager/cmd/controller/app/options"
	cmdutil "github.com/cert-manager/cert-manager/cmd/util"
	"github.com/cert-manager/cert-manager/internal/controller/feature"
	"github.com/cert-manager/cert-manager/pkg/acme/accounts"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/clusterissuers"
	dnsutil "github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/pkg/util/profiling"
)

func Run(opts *options.ControllerOptions, stopCh <-chan struct{}) error {
	rootCtx, cancelContext := context.WithCancel(cmdutil.ContextWithStopCh(context.Background(), stopCh))
	defer cancelContext()
	rootCtx = logf.NewContext(rootCtx, logf.Log, "controller")
	log := logf.FromContext(rootCtx)
	g, rootCtx := errgroup.WithContext(rootCtx)

	ctxFactory, err := buildControllerContextFactory(rootCtx, opts)
	if err != nil {
		return err
	}

	// Build the base controller context for the cert-manager controller manager
	// used here.
	ctx, err := ctxFactory.Build()
	if err != nil {
		return err
	}

	enabledControllers := opts.EnabledControllers()
	log.Info(fmt.Sprintf("enabled controllers: %s", enabledControllers.List()))

	// Start metrics server
	metricsLn, err := net.Listen("tcp", opts.MetricsListenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on prometheus address %s: %v", opts.MetricsListenAddress, err)
	}
	metricsServer := ctx.Metrics.NewServer(metricsLn)

	g.Go(func() error {
		<-rootCtx.Done()
		// allow a timeout for graceful shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := metricsServer.Shutdown(ctx); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		log.V(logf.InfoLevel).Info("starting metrics server", "address", metricsLn.Addr())
		if err := metricsServer.Serve(metricsLn); err != http.ErrServerClosed {
			return err
		}
		return nil
	})

	// Start profiler if it is enabled
	if opts.EnablePprof {
		profilerLn, err := net.Listen("tcp", opts.PprofAddress)
		if err != nil {
			return fmt.Errorf("failed to listen on profiler address %s: %v", opts.PprofAddress, err)
		}
		profilerMux := http.NewServeMux()
		// Add pprof endpoints to this mux
		profiling.Install(profilerMux)
		profilerServer := &http.Server{
			Handler: profilerMux,
		}

		g.Go(func() error {
			<-rootCtx.Done()
			// allow a timeout for graceful shutdown
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := profilerServer.Shutdown(ctx); err != nil {
				return err
			}
			return nil
		})
		g.Go(func() error {
			log.V(logf.InfoLevel).Info("starting profiler", "address", profilerLn.Addr())
			if err := profilerServer.Serve(profilerLn); err != http.ErrServerClosed {
				return err
			}
			return nil
		})
	}

	elected := make(chan struct{})
	if opts.LeaderElect {
		g.Go(func() error {
			log.V(logf.InfoLevel).Info("starting leader election")
			ctx, err := ctxFactory.Build("leader-election")
			if err != nil {
				return err
			}

			errorCh := make(chan error, 1)
			if err := startLeaderElection(rootCtx, opts, ctx.Client, ctx.Recorder, leaderelection.LeaderCallbacks{
				OnStartedLeading: func(_ context.Context) {
					close(elected)
				},
				OnStoppedLeading: func() {
					select {
					case <-rootCtx.Done():
						// context was canceled, just return
						return
					default:
						errorCh <- errors.New("leader election lost")
					}
				},
			}); err != nil {
				return err
			}

			select {
			case err := <-errorCh:
				return err
			default:
				return nil
			}
		})
	} else {
		close(elected)
	}

	select {
	case <-rootCtx.Done(): // Exit early if we are shutting down or if the errgroup has already exited with an error
		// Wait for error group to complete and return
		return g.Wait()
	case <-elected: // Don't launch the controllers unless we have been elected leader
		// Continue with setting up controller
	}

	for n, fn := range controller.Known() {
		log := log.WithValues("controller", n)

		// only run a controller if it's been enabled
		if !enabledControllers.Has(n) {
			log.V(logf.InfoLevel).Info("not starting controller as it's disabled")
			continue
		}

		// don't run clusterissuers controller if scoped to a single namespace
		if ctx.Namespace != "" && n == clusterissuers.ControllerName {
			log.V(logf.InfoLevel).Info("not starting controller as cert-manager has been scoped to a single namespace")
			continue
		}

		iface, err := fn(ctxFactory)
		if err != nil {
			err = fmt.Errorf("error starting controller: %v", err)

			cancelContext()
			err2 := g.Wait() // Don't process errors, we already have an error
			if err2 != nil {
				return utilerrors.NewAggregate([]error{err, err2})
			}
			return err
		}

		g.Go(func() error {
			log.V(logf.InfoLevel).Info("starting controller")

			// TODO: make this either a constant or a command line flag
			workers := 5
			return iface.Run(workers, rootCtx.Done())
		})
	}

	log.V(logf.DebugLevel).Info("starting shared informer factories")
	ctx.SharedInformerFactory.Start(rootCtx.Done())
	ctx.KubeSharedInformerFactory.Start(rootCtx.Done())

	if utilfeature.DefaultFeatureGate.Enabled(feature.ExperimentalGatewayAPISupport) {
		ctx.GWShared.Start(rootCtx.Done())
	}

	err = g.Wait()
	if err != nil {
		return fmt.Errorf("error starting controller: %v", err)
	}
	log.V(logf.InfoLevel).Info("control loops exited")

	return nil
}

// buildControllerContextFactory builds a new controller ContextFactory which
// can build controller contexts for each component.
func buildControllerContextFactory(ctx context.Context, opts *options.ControllerOptions) (*controller.ContextFactory, error) {
	log := logf.FromContext(ctx)

	nameservers := opts.DNS01RecursiveNameservers
	if len(nameservers) == 0 {
		nameservers = dnsutil.RecursiveNameservers
	}

	log.V(logf.InfoLevel).WithName("build-context").
		WithValues("nameservers", nameservers).
		Info("configured acme dns01 nameservers")

	http01SolverResourceRequestCPU, err := resource.ParseQuantity(opts.ACMEHTTP01SolverResourceRequestCPU)
	if err != nil {
		return nil, fmt.Errorf("error parsing ACMEHTTP01SolverResourceRequestCPU: %w", err)
	}

	http01SolverResourceRequestMemory, err := resource.ParseQuantity(opts.ACMEHTTP01SolverResourceRequestMemory)
	if err != nil {
		return nil, fmt.Errorf("error parsing ACMEHTTP01SolverResourceRequestMemory: %w", err)
	}

	http01SolverResourceLimitsCPU, err := resource.ParseQuantity(opts.ACMEHTTP01SolverResourceLimitsCPU)
	if err != nil {
		return nil, fmt.Errorf("error parsing ACMEHTTP01SolverResourceLimitsCPU: %w", err)
	}

	http01SolverResourceLimitsMemory, err := resource.ParseQuantity(opts.ACMEHTTP01SolverResourceLimitsMemory)
	if err != nil {
		return nil, fmt.Errorf("error parsing ACMEHTTP01SolverResourceLimitsMemory: %w", err)
	}

	acmeAccountRegistry := accounts.NewDefaultRegistry()

	ctxFactory, err := controller.NewContextFactory(ctx, controller.ContextOptions{
		Kubeconfig:         opts.Kubeconfig,
		KubernetesAPIQPS:   opts.KubernetesAPIQPS,
		KubernetesAPIBurst: opts.KubernetesAPIBurst,
		APIServerHost:      opts.APIServerHost,

		Namespace: opts.Namespace,

		Clock:   clock.RealClock{},
		Metrics: metrics.New(log, clock.RealClock{}),

		ACMEOptions: controller.ACMEOptions{
			HTTP01SolverResourceRequestCPU:    http01SolverResourceRequestCPU,
			HTTP01SolverResourceRequestMemory: http01SolverResourceRequestMemory,
			HTTP01SolverResourceLimitsCPU:     http01SolverResourceLimitsCPU,
			HTTP01SolverResourceLimitsMemory:  http01SolverResourceLimitsMemory,
			HTTP01SolverImage:                 opts.ACMEHTTP01SolverImage,
			// Allows specifying a list of custom nameservers to perform HTTP01 checks on.
			HTTP01SolverNameservers: opts.ACMEHTTP01SolverNameservers,

			DNS01Nameservers:        nameservers,
			DNS01CheckRetryPeriod:   opts.DNS01CheckRetryPeriod,
			DNS01CheckAuthoritative: !opts.DNS01RecursiveNameserversOnly,

			AccountRegistry: acmeAccountRegistry,
		},

		SchedulerOptions: controller.SchedulerOptions{
			MaxConcurrentChallenges: opts.MaxConcurrentChallenges,
		},

		IssuerOptions: controller.IssuerOptions{
			ClusterIssuerAmbientCredentials: opts.ClusterIssuerAmbientCredentials,
			IssuerAmbientCredentials:        opts.IssuerAmbientCredentials,
			ClusterResourceNamespace:        opts.ClusterResourceNamespace,
		},

		IngressShimOptions: controller.IngressShimOptions{
			DefaultIssuerName:                 opts.DefaultIssuerName,
			DefaultIssuerKind:                 opts.DefaultIssuerKind,
			DefaultIssuerGroup:                opts.DefaultIssuerGroup,
			DefaultAutoCertificateAnnotations: opts.DefaultAutoCertificateAnnotations,
		},

		CertificateOptions: controller.CertificateOptions{
			EnableOwnerRef:           opts.EnableCertificateOwnerRef,
			CopiedAnnotationPrefixes: opts.CopiedAnnotationPrefixes,
		},
	})
	if err != nil {
		return nil, err
	}

	return ctxFactory, nil
}

func startLeaderElection(ctx context.Context, opts *options.ControllerOptions, leaderElectionClient kubernetes.Interface, recorder record.EventRecorder, callbacks leaderelection.LeaderCallbacks) error {
	// Identity used to distinguish between multiple controller manager instances
	id, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("error getting hostname: %v", err)
	}

	lockName := "cert-manager-controller"
	lc := resourcelock.ResourceLockConfig{
		Identity:      id + "-external-cert-manager-controller",
		EventRecorder: recorder,
	}

	// We only support leases for leader election. Previously we supported ConfigMap & Lease objects for leader
	// election.
	ml, err := resourcelock.New(resourcelock.LeasesResourceLock,
		opts.LeaderElectionNamespace,
		lockName,
		leaderElectionClient.CoreV1(),
		leaderElectionClient.CoordinationV1(),
		lc,
	)
	if err != nil {
		return fmt.Errorf("error creating leader election lock: %v", err)
	}

	// Try and become the leader and start controller manager loops
	le, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:            ml,
		LeaseDuration:   opts.LeaderElectionLeaseDuration,
		RenewDeadline:   opts.LeaderElectionRenewDeadline,
		RetryPeriod:     opts.LeaderElectionRetryPeriod,
		ReleaseOnCancel: true,
		Callbacks:       callbacks,
	})
	if err != nil {
		return err
	}

	le.Run(ctx)

	return nil
}
