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
	"os"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/cmd/controller/app/options"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	intscheme "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/scheme"
	informers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/clusterissuers"
	dnsutil "github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	kubeinformers "k8s.io/client-go/informers"
)

const controllerAgentName = "cert-manager"

func Run(opts *options.ControllerOptions, stopCh <-chan struct{}) {
	rootCtx := util.ContextWithStopCh(context.Background(), stopCh)
	rootCtx = logf.NewContext(rootCtx, nil, "controller")
	log := logf.FromContext(rootCtx)

	ctx, kubeCfg, err := buildControllerContext(rootCtx, stopCh, opts)

	if err != nil {
		log.Error(err, "error building controller context", "options", opts)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		metrics.Default.Start(stopCh)
	}()

	run := func(_ context.Context) {
		for n, fn := range controller.Known() {
			log := log.WithValues("controller", n)

			// only run a controller if it's been enabled
			if !util.Contains(opts.EnabledControllers, n) {
				log.Info("not starting controller as it's disabled")
				continue
			}

			// don't run clusterissuers controller if scoped to a single namespace
			if ctx.Namespace != "" && n == clusterissuers.ControllerName {
				log.Info("not starting controller as cert-manager has been scoped to a single namespace")
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
				log.Info("starting controller")

				workers := 5
				err := fn(workers, stopCh)

				if err != nil {
					log.Error(err, "error starting controller")
					os.Exit(1)
				}
			}(n, iface)
		}

		log.V(4).Info("starting shared informer factories")
		ctx.SharedInformerFactory.Start(stopCh)
		ctx.KubeSharedInformerFactory.Start(stopCh)
		wg.Wait()
		log.Info("control loops exited")
		os.Exit(0)
	}

	if !opts.LeaderElect {
		run(context.TODO())
		return
	}

	log.Info("starting leader election")
	leaderElectionClient, err := kubernetes.NewForConfig(rest.AddUserAgent(kubeCfg, "leader-election"))
	if err != nil {
		log.Error(err, "error creating leader election client")
		os.Exit(1)
	}

	startLeaderElection(rootCtx, opts, leaderElectionClient, ctx.Recorder, run)
	panic("unreachable")
}

func buildControllerContext(ctx context.Context, stopCh <-chan struct{}, opts *options.ControllerOptions) (*controller.Context, *rest.Config, error) {
	log := logf.FromContext(ctx, "build-context")
	// Load the users Kubernetes config
	kubeCfg, err := kube.KubeConfig(opts.APIServerHost)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating rest config: %s", err.Error())
	}

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

	nameservers := opts.DNS01RecursiveNameservers
	if len(nameservers) == 0 {
		nameservers = dnsutil.RecursiveNameservers
	}
	log.WithValues("nameservers", nameservers).Info("configured acme dns01 nameservers")

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
	log.V(4).Info("creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.V(4).Infof)
	eventBroadcaster.StartRecordingToSink(&corev1.EventSinkImpl{Interface: cl.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: controllerAgentName})

	sharedInformerFactory := informers.NewFilteredSharedInformerFactory(intcl, time.Second*30, opts.Namespace, nil)
	kubeSharedInformerFactory := kubeinformers.NewFilteredSharedInformerFactory(cl, time.Second*30, opts.Namespace, nil)
	return &controller.Context{
		RootContext:               ctx,
		StopCh:                    stopCh,
		RESTConfig:                kubeCfg,
		Client:                    cl,
		CMClient:                  intcl,
		Recorder:                  recorder,
		KubeSharedInformerFactory: kubeSharedInformerFactory,
		SharedInformerFactory:     sharedInformerFactory,
		Namespace:                 opts.Namespace,
		ACMEOptions: controller.ACMEOptions{
			HTTP01SolverImage:                 opts.ACMEHTTP01SolverImage,
			HTTP01SolverResourceRequestCPU:    HTTP01SolverResourceRequestCPU,
			HTTP01SolverResourceRequestMemory: HTTP01SolverResourceRequestMemory,
			HTTP01SolverResourceLimitsCPU:     HTTP01SolverResourceLimitsCPU,
			HTTP01SolverResourceLimitsMemory:  HTTP01SolverResourceLimitsMemory,
			DNS01CheckAuthoritative:           !opts.DNS01RecursiveNameserversOnly,
			DNS01Nameservers:                  nameservers,
		},
		IssuerOptions: controller.IssuerOptions{
			ClusterIssuerAmbientCredentials: opts.ClusterIssuerAmbientCredentials,
			IssuerAmbientCredentials:        opts.IssuerAmbientCredentials,
			ClusterResourceNamespace:        opts.ClusterResourceNamespace,
			RenewBeforeExpiryDuration:       opts.RenewBeforeExpiryDuration,
		},
		IngressShimOptions: controller.IngressShimOptions{
			DefaultIssuerName:                  opts.DefaultIssuerName,
			DefaultIssuerKind:                  opts.DefaultIssuerKind,
			DefaultAutoCertificateAnnotations:  opts.DefaultAutoCertificateAnnotations,
			DefaultACMEIssuerChallengeType:     opts.DefaultACMEIssuerChallengeType,
			DefaultACMEIssuerDNS01ProviderName: opts.DefaultACMEIssuerDNS01ProviderName,
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

	// Lock required for leader election
	rl := resourcelock.ConfigMapLock{
		ConfigMapMeta: metav1.ObjectMeta{
			Namespace: opts.LeaderElectionNamespace,
			Name:      "cert-manager-controller",
		},
		Client: leaderElectionClient.CoreV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity:      id + "-external-cert-manager-controller",
			EventRecorder: recorder,
		},
	}

	// Try and become the leader and start controller manager loops
	leaderelection.RunOrDie(context.TODO(), leaderelection.LeaderElectionConfig{
		Lock:          &rl,
		LeaseDuration: opts.LeaderElectionLeaseDuration,
		RenewDeadline: opts.LeaderElectionRenewDeadline,
		RetryPeriod:   opts.LeaderElectionRetryPeriod,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: run,
			OnStoppedLeading: func() {
				log.Info("leader election lost")
				os.Exit(1)
			},
		},
	})
}
