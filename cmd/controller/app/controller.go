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
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	kubeinformers "k8s.io/client-go/informers"
)

const controllerAgentName = "cert-manager"

func Run(opts *options.ControllerOptions, stopCh <-chan struct{}) {
	ctx, kubeCfg, err := buildControllerContext(opts)

	if err != nil {
		klog.Fatalf(err.Error())
	}

	run := func(_ context.Context) {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			metrics.Default.Start(stopCh)
		}()
		for n, fn := range controller.Known() {
			// only run a controller if it's been enabled
			if !util.Contains(opts.EnabledControllers, n) {
				klog.Infof("%s controller is not in list of controllers to enable, so not enabling it", n)
				continue
			}

			// don't run clusterissuers controller if scoped to a single namespace
			if ctx.Namespace != "" && n == clusterissuers.ControllerName {
				klog.Infof("Skipping ClusterIssuer controller as cert-manager is scoped to a single namespace")
				continue
			}

			wg.Add(1)
			go func(n string, fn controller.Interface) {
				defer wg.Done()
				klog.Infof("Starting %s controller", n)

				workers := 5
				err := fn(workers, stopCh)

				if err != nil {
					klog.Fatalf("error running %s controller: %s", n, err.Error())
				}
			}(n, fn(ctx))
		}
		klog.V(4).Infof("Starting shared informer factory")
		ctx.SharedInformerFactory.Start(stopCh)
		ctx.KubeSharedInformerFactory.Start(stopCh)
		wg.Wait()
		klog.Fatalf("Control loops exited")
	}

	if !opts.LeaderElect {
		run(context.TODO())
		return
	}

	leaderElectionClient, err := kubernetes.NewForConfig(rest.AddUserAgent(kubeCfg, "leader-election"))

	if err != nil {
		klog.Fatalf("error creating leader election client: %s", err.Error())
	}

	startLeaderElection(opts, leaderElectionClient, ctx.Recorder, run)
	panic("unreachable")
}

func buildControllerContext(opts *options.ControllerOptions) (*controller.Context, *rest.Config, error) {
	// Load the users Kubernetes config
	kubeCfg, err := kube.KubeConfig(opts.APIServerHost)

	if err != nil {
		return nil, nil, fmt.Errorf("error creating rest config: %s", err.Error())
	}

	// Create a Navigator api client
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

	klog.Infof("Using the following nameservers for DNS01 checks: %v", nameservers)

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
	klog.V(4).Info("Creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.V(4).Infof)
	eventBroadcaster.StartRecordingToSink(&corev1.EventSinkImpl{Interface: cl.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: controllerAgentName})

	sharedInformerFactory := informers.NewFilteredSharedInformerFactory(intcl, time.Second*30, opts.Namespace, nil)
	kubeSharedInformerFactory := kubeinformers.NewFilteredSharedInformerFactory(cl, time.Second*30, opts.Namespace, nil)
	return &controller.Context{
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
	}, kubeCfg, nil
}

func startLeaderElection(opts *options.ControllerOptions, leaderElectionClient kubernetes.Interface, recorder record.EventRecorder, run func(context.Context)) {
	// Identity used to distinguish between multiple controller manager instances
	id, err := os.Hostname()
	if err != nil {
		klog.Fatalf("error getting hostname: %s", err.Error())
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
				klog.Fatalf("leaderelection lost")
			},
		},
	})
}
