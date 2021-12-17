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
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	clientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	gwapi "sigs.k8s.io/gateway-api/apis/v1alpha1"
	gwclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gwscheme "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/scheme"
	gwinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"

	"github.com/jetstack/cert-manager/cmd/controller/app/options"
	cmdutil "github.com/jetstack/cert-manager/cmd/util"
	"github.com/jetstack/cert-manager/internal/controller/feature"
	"github.com/jetstack/cert-manager/pkg/acme/accounts"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	intscheme "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/scheme"
	informers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/clusterissuers"
	dnsutil "github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/pkg/util"
	utilfeature "github.com/jetstack/cert-manager/pkg/util/feature"
	"github.com/jetstack/cert-manager/pkg/util/profiling"
)

const controllerAgentName = "cert-manager"

// This sets the informer's resync period to 10 hours
// following the controller-runtime defaults
//and following discussion: https://github.com/kubernetes-sigs/controller-runtime/pull/88#issuecomment-408500629
const resyncPeriod = 10 * time.Hour

func Run(opts *options.ControllerOptions, stopCh <-chan struct{}) error {
	rootCtx, cancelContext := context.WithCancel(cmdutil.ContextWithStopCh(context.Background(), stopCh))
	defer cancelContext()
	rootCtx = logf.NewContext(rootCtx, logf.Log, "controller")
	log := logf.FromContext(rootCtx)
	g, rootCtx := errgroup.WithContext(rootCtx)

	ctx, kubeCfg, err := buildControllerContext(rootCtx, opts)
	if err != nil {
		return fmt.Errorf("error building controller context (options %v): %v", opts, err)
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
			leaderElectionClient, err := kubernetes.NewForConfig(rest.AddUserAgent(kubeCfg, "leader-election"))
			if err != nil {
				return fmt.Errorf("error creating leader election client: %v", err)
			}

			errorCh := make(chan error, 1)
			if err := startLeaderElection(rootCtx, opts, leaderElectionClient, ctx.Recorder, leaderelection.LeaderCallbacks{
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

		iface, err := fn(ctx)
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

func buildControllerContext(ctx context.Context, opts *options.ControllerOptions) (*controller.Context, *rest.Config, error) {
	log := logf.FromContext(ctx, "build-context")
	// Load the users Kubernetes config
	kubeCfg, err := clientcmd.BuildConfigFromFlags(opts.APIServerHost, opts.Kubeconfig)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating rest config: %s", err.Error())
	}

	kubeCfg.QPS = opts.KubernetesAPIQPS
	kubeCfg.Burst = opts.KubernetesAPIBurst

	// Add User-Agent to client
	kubeCfg = rest.AddUserAgent(kubeCfg, util.CertManagerUserAgent)

	// Create a cert-manager api client
	intcl, err := clientset.NewForConfig(kubeCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating internal group client: %s", err.Error())
	}

	// Create a Kubernetes api client
	cl, err := kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating kubernetes client: %s", err.Error())
	}

	var gatewayAvailable bool
	// Check if the Gateway API feature gate was enabled
	if utilfeature.DefaultFeatureGate.Enabled(feature.ExperimentalGatewayAPISupport) {
		// check if the gateway API CRDs are available. If they are not found return an error
		// which will cause cert-manager to crashloopbackoff
		d := cl.Discovery()
		resources, err := d.ServerResourcesForGroupVersion(gwapi.GroupVersion.String())
		var GatewayAPINotAvailable = "the Gateway API CRDs do not seem to be present, but " + feature.ExperimentalGatewayAPISupport +
			" is set to true. Please install the gateway-api CRDs."
		switch {
		case apierrors.IsNotFound(err):
			return nil, nil, fmt.Errorf("%s (%w)", GatewayAPINotAvailable, err)
		case err != nil:
			return nil, nil, fmt.Errorf("while checking if the Gateway API CRD is installed: %w", err)
		case len(resources.APIResources) == 0:
			return nil, nil, fmt.Errorf("%s (found %d APIResources in %s)", GatewayAPINotAvailable, len(resources.APIResources), gwapi.GroupVersion.String())
		default:
			gatewayAvailable = true
		}
	}

	// Create a GatewayAPI client.
	gwcl, err := gwclient.NewForConfig(kubeCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating kubernetes client: %s", err.Error())
	}

	nameservers := opts.DNS01RecursiveNameservers
	if len(nameservers) == 0 {
		nameservers = dnsutil.RecursiveNameservers
	}
	log.V(logf.InfoLevel).WithValues("nameservers", nameservers).Info("configured acme dns01 nameservers")

	HTTP01SolverResourceRequestCPU, err := resource.ParseQuantity(opts.ACMEHTTP01SolverResourceRequestCPU)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing ACMEHTTP01SolverResourceRequestCPU: %s", err.Error())
	}

	HTTP01SolverResourceRequestMemory, err := resource.ParseQuantity(opts.ACMEHTTP01SolverResourceRequestMemory)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing ACMEHTTP01SolverResourceRequestMemory: %s", err.Error())
	}

	HTTP01SolverResourceLimitsCPU, err := resource.ParseQuantity(opts.ACMEHTTP01SolverResourceLimitsCPU)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing ACMEHTTP01SolverResourceLimitsCPU: %s", err.Error())
	}

	HTTP01SolverResourceLimitsMemory, err := resource.ParseQuantity(opts.ACMEHTTP01SolverResourceLimitsMemory)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing ACMEHTTP01SolverResourceLimitsMemory: %s", err.Error())
	}

	// Create event broadcaster
	// Add cert-manager types to the default Kubernetes Scheme so Events can be
	// logged properly
	intscheme.AddToScheme(scheme.Scheme)
	gwscheme.AddToScheme(scheme.Scheme)
	log.V(logf.DebugLevel).Info("creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(logf.WithInfof(log.V(logf.DebugLevel)).Infof)
	eventBroadcaster.StartRecordingToSink(&clientv1.EventSinkImpl{Interface: cl.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})

	sharedInformerFactory := informers.NewSharedInformerFactoryWithOptions(intcl, resyncPeriod, informers.WithNamespace(opts.Namespace))
	kubeSharedInformerFactory := kubeinformers.NewSharedInformerFactoryWithOptions(cl, resyncPeriod, kubeinformers.WithNamespace(opts.Namespace))
	gwSharedInformerFactory := gwinformers.NewSharedInformerFactoryWithOptions(gwcl, resyncPeriod, gwinformers.WithNamespace(opts.Namespace))

	acmeAccountRegistry := accounts.NewDefaultRegistry()

	return &controller.Context{
		RootContext:               ctx,
		StopCh:                    ctx.Done(),
		RESTConfig:                kubeCfg,
		Client:                    cl,
		CMClient:                  intcl,
		GWClient:                  gwcl,
		DiscoveryClient:           cl.Discovery(),
		Recorder:                  recorder,
		KubeSharedInformerFactory: kubeSharedInformerFactory,
		SharedInformerFactory:     sharedInformerFactory,
		GWShared:                  gwSharedInformerFactory,
		GatewaySolverEnabled:      gatewayAvailable,
		Namespace:                 opts.Namespace,
		Clock:                     clock.RealClock{},
		Metrics:                   metrics.New(log, clock.RealClock{}),
		ACMEOptions: controller.ACMEOptions{
			HTTP01SolverImage:                 opts.ACMEHTTP01SolverImage,
			HTTP01SolverResourceRequestCPU:    HTTP01SolverResourceRequestCPU,
			HTTP01SolverResourceRequestMemory: HTTP01SolverResourceRequestMemory,
			HTTP01SolverResourceLimitsCPU:     HTTP01SolverResourceLimitsCPU,
			HTTP01SolverResourceLimitsMemory:  HTTP01SolverResourceLimitsMemory,
			DNS01CheckAuthoritative:           !opts.DNS01RecursiveNameserversOnly,
			DNS01Nameservers:                  nameservers,
			AccountRegistry:                   acmeAccountRegistry,
			DNS01CheckRetryPeriod:             opts.DNS01CheckRetryPeriod,
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
		SchedulerOptions: controller.SchedulerOptions{
			MaxConcurrentChallenges: opts.MaxConcurrentChallenges,
		},
	}, kubeCfg, nil
}

func startLeaderElection(ctx context.Context, opts *options.ControllerOptions, leaderElectionClient kubernetes.Interface, recorder record.EventRecorder, callbacks leaderelection.LeaderCallbacks) error {
	// Identity used to distinguish between multiple controller manager instances
	id, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("error getting hostname: %v", err)
	}

	// Set up Multilock for leader election. This Multilock is here for the
	// transitionary period from configmaps to leases see
	// https://github.com/kubernetes-sigs/controller-runtime/pull/1144#discussion_r480173688
	lockName := "cert-manager-controller"
	lc := resourcelock.ResourceLockConfig{
		Identity:      id + "-external-cert-manager-controller",
		EventRecorder: recorder,
	}
	ml, err := resourcelock.New(resourcelock.ConfigMapsLeasesResourceLock,
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
