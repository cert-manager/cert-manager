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
	"os"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
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
)

const controllerAgentName = "cert-manager"

// This sets the informer's resync period to 10 hours
// following the controller-runtime defaults
//and following discussion: https://github.com/kubernetes-sigs/controller-runtime/pull/88#issuecomment-408500629
const resyncPeriod = 10 * time.Hour

func Run(opts *options.ControllerOptions, stopCh <-chan struct{}) {
	rootCtx := util.ContextWithStopCh(context.Background(), stopCh)
	rootCtx = logf.NewContext(rootCtx, nil, "controller")
	log := logf.FromContext(rootCtx)

	ctx, kubeCfg, err := buildControllerContext(rootCtx, stopCh, opts)
	if err != nil {
		log.Error(err, "error building controller context", "options", opts)
		os.Exit(1)
	}

	enabledControllers := opts.EnabledControllers()
	log.Info(fmt.Sprintf("enabled controllers: %s", enabledControllers.List()))

	metricsServer, err := ctx.Metrics.Start(opts.MetricsListenAddress, opts.EnablePprof)
	if err != nil {
		log.Error(err, "failed to listen on prometheus address", "address", opts.MetricsListenAddress)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	run := func(_ context.Context) {
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

			wg.Add(1)
			iface, err := fn(ctx)
			if err != nil {
				log.Error(err, "error starting controller")
				os.Exit(1)
			}
			go func(n string, fn controller.Interface) {
				defer wg.Done()
				log.V(logf.InfoLevel).Info("starting controller")

				workers := 5
				err := fn.Run(workers, stopCh)

				if err != nil {
					log.Error(err, "error starting controller")
					os.Exit(1)
				}
			}(n, iface)
		}

		log.V(logf.DebugLevel).Info("starting shared informer factories")
		ctx.SharedInformerFactory.Start(stopCh)
		ctx.KubeSharedInformerFactory.Start(stopCh)
		ctx.GWShared.Start(stopCh)
		wg.Wait()
		log.V(logf.InfoLevel).Info("control loops exited")
		ctx.Metrics.Shutdown(metricsServer)
		os.Exit(0)
	}

	if !opts.LeaderElect {
		run(context.TODO())
		return
	}

	log.V(logf.InfoLevel).Info("starting leader election")
	leaderElectionClient, err := kubernetes.NewForConfig(rest.AddUserAgent(kubeCfg, "leader-election"))
	if err != nil {
		log.Error(err, "error creating leader election client")
		os.Exit(1)
	}

	startLeaderElection(rootCtx, opts, leaderElectionClient, ctx.Recorder, run)
}

func buildControllerContext(ctx context.Context, stopCh <-chan struct{}, opts *options.ControllerOptions) (*controller.Context, *rest.Config, error) {
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

	// The user may have enabled the gateway-shim controller but forgotten to
	// install the Gateway API CRDs. Failing here will cause cert-manager to go
	// into CrashLoopBackoff which is nice and obvious.
	d := cl.Discovery()
	resources, err := d.ServerResourcesForGroupVersion(gwapi.GroupVersion.String())
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't discover Gateway API resources (are the Gateway API CRDs installed?): %w", err)
	}
	if len(resources.APIResources) == 0 {
		return nil, nil, fmt.Errorf("no gateway API resources were discovered (are the Gateway API CRDs installed?)")
	}

	// Create a GatewayAPI client
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
		StopCh:                    stopCh,
		RESTConfig:                kubeCfg,
		Client:                    cl,
		CMClient:                  intcl,
		GWClient:                  gwcl,
		Recorder:                  recorder,
		KubeSharedInformerFactory: kubeSharedInformerFactory,
		SharedInformerFactory:     sharedInformerFactory,
		GWShared:                  gwSharedInformerFactory,
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
			EnableOwnerRef: opts.EnableCertificateOwnerRef,
		},
		SchedulerOptions: controller.SchedulerOptions{
			MaxConcurrentChallenges: opts.MaxConcurrentChallenges,
		},
	}, kubeCfg, nil
}

func startLeaderElection(ctx context.Context, opts *options.ControllerOptions, leaderElectionClient kubernetes.Interface, recorder record.EventRecorder, run func(context.Context)) {
	log := logf.FromContext(ctx, "leader-election")

	// Identity used to distinguish between multiple controller manager instances
	id, err := os.Hostname()
	if err != nil {
		log.Error(err, "error getting hostname")
		os.Exit(1)
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
		// We should never get here.
		log.Error(err, "error creating leader election lock")
		os.Exit(1)

	}

	// Try and become the leader and start controller manager loops
	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:          ml,
		LeaseDuration: opts.LeaderElectionLeaseDuration,
		RenewDeadline: opts.LeaderElectionRenewDeadline,
		RetryPeriod:   opts.LeaderElectionRetryPeriod,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: run,
			OnStoppedLeading: func() {
				log.V(logf.ErrorLevel).Info("leader election lost")
				os.Exit(1)
			},
		},
	})
}
