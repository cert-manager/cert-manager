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

	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/api/resource"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"

	"github.com/cert-manager/cert-manager/controller-binary/app/options"
	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
	"github.com/cert-manager/cert-manager/internal/apis/config/shared"
	"github.com/cert-manager/cert-manager/internal/controller/feature"
	"github.com/cert-manager/cert-manager/pkg/acme/accounts"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/healthz"
	dnsutil "github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	"github.com/cert-manager/cert-manager/pkg/server"
	"github.com/cert-manager/cert-manager/pkg/server/tls"
	"github.com/cert-manager/cert-manager/pkg/server/tls/authority"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/pkg/util/profiling"
)

const (
	// This is intended to mitigate "slowloris" attacks by limiting the time a
	// deliberately slow client can spend sending HTTP headers.
	// This default value is copied from:
	// * kubernetes api-server:
	//   https://github.com/kubernetes/kubernetes/blob/9e028b40b9e970142191259effe796b3dab39828/staging/src/k8s.io/apiserver/pkg/server/secure_serving.go#L165-L173
	// * controller-runtime:
	//   https://github.com/kubernetes-sigs/controller-runtime/blob/1ea2be573f7887a9fbd766e9a921c5af344da6eb/pkg/internal/httpserver/server.go#L14
	defaultReadHeaderTimeout = 32 * time.Second
)

func Run(rootCtx context.Context, opts *config.ControllerConfiguration) error {
	rootCtx, cancelContext := context.WithCancel(rootCtx)
	defer cancelContext()

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

	enabledControllers := options.EnabledControllers(opts)
	log.Info(fmt.Sprintf("enabled controllers: %s", sets.List(enabledControllers)))

	// start the CertificateSource if provided
	certificateSource := buildCertificateSource(log, opts.MetricsTLSConfig, ctx.RESTConfig)
	if certificateSource != nil {
		log.V(logf.InfoLevel).Info("listening for secure connections", "address", opts.MetricsListenAddress)
		g.Go(func() error {
			if err := certificateSource.Start(rootCtx); (err != nil) && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		})
	} else {
		log.V(logf.InfoLevel).Info("listening for insecure connections", "address", opts.MetricsListenAddress)
	}

	// Start metrics server
	metricsLn, err := server.Listen("tcp", opts.MetricsListenAddress,
		server.WithCertificateSource(certificateSource),
		server.WithTLSCipherSuites(opts.MetricsTLSConfig.CipherSuites),
		server.WithTLSMinVersion(opts.MetricsTLSConfig.MinTLSVersion),
	)
	if err != nil {
		return fmt.Errorf("failed to listen on prometheus address %s: %v", opts.MetricsListenAddress, err)
	}
	metricsServer := ctx.Metrics.NewServer(metricsLn)

	g.Go(func() error {
		<-rootCtx.Done()
		// allow a timeout for graceful shutdown
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// nolint: contextcheck
		return metricsServer.Shutdown(shutdownCtx)
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
			Handler:           profilerMux,
			ReadHeaderTimeout: defaultReadHeaderTimeout, // Mitigation for G112: Potential slowloris attack
		}

		g.Go(func() error {
			<-rootCtx.Done()
			// allow a timeout for graceful shutdown
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// nolint: contextcheck
			return profilerServer.Shutdown(shutdownCtx)
		})
		g.Go(func() error {
			log.V(logf.InfoLevel).Info("starting profiler", "address", profilerLn.Addr())
			if err := profilerServer.Serve(profilerLn); err != http.ErrServerClosed {
				return err
			}
			return nil
		})
	}
	healthzListener, err := net.Listen("tcp", opts.HealthzListenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on healthz address %s: %v", opts.HealthzListenAddress, err)
	}
	healthzServer := healthz.NewServer(opts.LeaderElectionConfig.HealthzTimeout)
	g.Go(func() error {
		log.V(logf.InfoLevel).Info("starting healthz server", "address", healthzListener.Addr())
		return healthzServer.Start(rootCtx, healthzListener)
	})

	elected := make(chan struct{})
	if opts.LeaderElectionConfig.Enabled {
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
			}, healthzServer.LeaderHealthzAdaptor); err != nil {
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
			log.V(logf.InfoLevel).Info("skipping disabled controller")
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

			return iface.Run(opts.NumberOfConcurrentWorkers, rootCtx)
		})
	}

	log.V(logf.DebugLevel).Info("starting shared informer factories")
	ctx.SharedInformerFactory.Start(rootCtx.Done())
	ctx.KubeSharedInformerFactory.Start(rootCtx.Done())
	ctx.HTTP01ResourceMetadataInformersFactory.Start(rootCtx.Done())

	if utilfeature.DefaultFeatureGate.Enabled(feature.ExperimentalGatewayAPISupport) && opts.EnableGatewayAPI {
		ctx.GWShared.Start(rootCtx.Done())
	}

	err = g.Wait()
	if err != nil {
		return fmt.Errorf("error starting controller: %v", err)
	}
	log.V(logf.InfoLevel).Info("control loops exited")

	if utilfeature.DefaultFeatureGate.Enabled(feature.ExperimentalGatewayAPISupport) && opts.EnableGatewayAPI {
		ctx.GWShared.Shutdown()
	}

	ctx.HTTP01ResourceMetadataInformersFactory.Shutdown()
	ctx.KubeSharedInformerFactory.Shutdown()
	ctx.SharedInformerFactory.Shutdown()

	return nil
}

// buildControllerContextFactory builds a new controller ContextFactory which
// can build controller contexts for each component.
func buildControllerContextFactory(ctx context.Context, opts *config.ControllerConfiguration) (*controller.ContextFactory, error) {
	log := logf.FromContext(ctx)

	nameservers := opts.ACMEDNS01Config.RecursiveNameservers
	if len(nameservers) == 0 {
		nameservers = dnsutil.RecursiveNameservers
	}

	log.V(logf.InfoLevel).WithName("build-context").
		WithValues("nameservers", nameservers).
		Info("configured acme dns01 nameservers")

	http01SolverResourceRequestCPU, err := resource.ParseQuantity(opts.ACMEHTTP01Config.SolverResourceRequestCPU)
	if err != nil {
		return nil, fmt.Errorf("error parsing ACMEHTTP01SolverResourceRequestCPU: %w", err)
	}

	http01SolverResourceRequestMemory, err := resource.ParseQuantity(opts.ACMEHTTP01Config.SolverResourceRequestMemory)
	if err != nil {
		return nil, fmt.Errorf("error parsing ACMEHTTP01SolverResourceRequestMemory: %w", err)
	}

	http01SolverResourceLimitsCPU, err := resource.ParseQuantity(opts.ACMEHTTP01Config.SolverResourceLimitsCPU)
	if err != nil {
		return nil, fmt.Errorf("error parsing ACMEHTTP01SolverResourceLimitsCPU: %w", err)
	}

	http01SolverResourceLimitsMemory, err := resource.ParseQuantity(opts.ACMEHTTP01Config.SolverResourceLimitsMemory)
	if err != nil {
		return nil, fmt.Errorf("error parsing ACMEHTTP01SolverResourceLimitsMemory: %w", err)
	}

	ACMEHTTP01SolverRunAsNonRoot := opts.ACMEHTTP01Config.SolverRunAsNonRoot
	acmeAccountRegistry := accounts.NewDefaultRegistry()

	ctxFactory, err := controller.NewContextFactory(ctx, controller.ContextOptions{
		Kubeconfig:         opts.KubeConfig,
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
			ACMEHTTP01SolverRunAsNonRoot:      ACMEHTTP01SolverRunAsNonRoot,
			HTTP01SolverImage:                 opts.ACMEHTTP01Config.SolverImage,
			// Allows specifying a list of custom nameservers to perform HTTP01 checks on.
			HTTP01SolverNameservers: opts.ACMEHTTP01Config.SolverNameservers,

			DNS01Nameservers:        nameservers,
			DNS01CheckRetryPeriod:   opts.ACMEDNS01Config.CheckRetryPeriod,
			DNS01CheckAuthoritative: !opts.ACMEDNS01Config.RecursiveNameserversOnly,

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
			DefaultIssuerName:                 opts.IngressShimConfig.DefaultIssuerName,
			DefaultIssuerKind:                 opts.IngressShimConfig.DefaultIssuerKind,
			DefaultIssuerGroup:                opts.IngressShimConfig.DefaultIssuerGroup,
			DefaultAutoCertificateAnnotations: opts.IngressShimConfig.DefaultAutoCertificateAnnotations,
			ExtraCertificateAnnotations:       opts.IngressShimConfig.ExtraCertificateAnnotations,
		},

		CertificateOptions: controller.CertificateOptions{
			EnableOwnerRef:           opts.EnableCertificateOwnerRef,
			CopiedAnnotationPrefixes: opts.CopiedAnnotationPrefixes,
		},

		ConfigOptions: controller.ConfigOptions{
			EnableGatewayAPI: opts.EnableGatewayAPI,
		},
	})
	if err != nil {
		return nil, err
	}

	return ctxFactory, nil
}

func startLeaderElection(ctx context.Context, opts *config.ControllerConfiguration, leaderElectionClient kubernetes.Interface, recorder record.EventRecorder, callbacks leaderelection.LeaderCallbacks, healthzAdaptor *leaderelection.HealthzAdaptor) error {
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
		opts.LeaderElectionConfig.Namespace,
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
		LeaseDuration:   opts.LeaderElectionConfig.LeaseDuration,
		RenewDeadline:   opts.LeaderElectionConfig.RenewDeadline,
		RetryPeriod:     opts.LeaderElectionConfig.RetryPeriod,
		ReleaseOnCancel: true,
		Callbacks:       callbacks,
		WatchDog:        healthzAdaptor,
	})
	if err != nil {
		return err
	}

	le.Run(ctx)

	return nil
}

func buildCertificateSource(log logr.Logger, tlsConfig shared.TLSConfig, restCfg *rest.Config) tls.CertificateSource {
	switch {
	case tlsConfig.FilesystemConfigProvided():
		log.V(logf.InfoLevel).Info("using TLS certificate from local filesystem", "private_key_path", tlsConfig.Filesystem.KeyFile, "certificate", tlsConfig.Filesystem.CertFile)
		return &tls.FileCertificateSource{
			CertPath: tlsConfig.Filesystem.CertFile,
			KeyPath:  tlsConfig.Filesystem.KeyFile,
		}
	case tlsConfig.DynamicConfigProvided():
		log.V(logf.InfoLevel).Info("using dynamic certificate generating using CA stored in Secret resource", "secret_namespace", tlsConfig.Dynamic.SecretNamespace, "secret_name", tlsConfig.Dynamic.SecretName)
		return &tls.DynamicSource{
			DNSNames: tlsConfig.Dynamic.DNSNames,
			Authority: &authority.DynamicAuthority{
				SecretNamespace: tlsConfig.Dynamic.SecretNamespace,
				SecretName:      tlsConfig.Dynamic.SecretName,
				SecretLabels:    map[string]string{"app.kubernetes.io/managed-by": "cert-manager"},
				LeafDuration:    tlsConfig.Dynamic.LeafDuration,
				RESTConfig:      restCfg,
			},
		}
	default:
		log.V(logf.WarnLevel).Info("serving insecurely as tls certificate data not provided")
	}
	return nil
}
