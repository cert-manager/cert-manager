/*
Copyright 2018 The Jetstack cert-manager contributors.

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
	"os"
	"sync"
	"time"

	"github.com/golang/glog"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"

	"github.com/jetstack/cert-manager/cmd/controller/app/options"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	intscheme "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/scheme"
	informers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
	"github.com/jetstack/cert-manager/pkg/controller"
	dnsutil "github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	kubeinformers "k8s.io/client-go/informers"
)

const controllerAgentName = "cert-manager"

func Run(opts *options.ControllerOptions, stopCh <-chan struct{}) {
	ctx, kubeCfg, err := buildControllerContext(opts)

	if err != nil {
		glog.Fatalf(err.Error())
	}

	run := func(_ <-chan struct{}) {
		var wg sync.WaitGroup
		for n, fn := range controller.Known() {
			// only run a controller if it's been enabled
			if !util.Contains(opts.EnabledControllers, n) {
				glog.Infof("%s controller is not in list of controllers to enable, so not enabling it", n)
				continue
			}

			wg.Add(1)
			go func(n string, fn controller.Interface) {
				defer wg.Done()
				glog.Infof("Starting %s controller", n)

				err := fn(5, stopCh)

				if err != nil {
					glog.Fatalf("error running %s controller: %s", n, err.Error())
				}
			}(n, fn(ctx))
		}
		glog.V(4).Infof("Starting shared informer factory")
		ctx.SharedInformerFactory.Start(stopCh)
		ctx.KubeSharedInformerFactory.Start(stopCh)
		wg.Wait()
		glog.Fatalf("Control loops exited")
	}

	if !opts.LeaderElect {
		run(stopCh)
		return
	}

	leaderElectionClient, err := kubernetes.NewForConfig(rest.AddUserAgent(kubeCfg, "leader-election"))

	if err != nil {
		glog.Fatalf("error creating leader election client: %s", err.Error())
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

	nameservers := opts.DNS01Nameservers
	if len(nameservers) == 0 {
		nameservers = dnsutil.RecursiveNameservers
	}

	glog.Infof("Using the following nameservers for DNS01 checks: %v", nameservers)

	// Create event broadcaster
	// Add cert-manager types to the default Kubernetes Scheme so Events can be
	// logged properly
	intscheme.AddToScheme(scheme.Scheme)
	glog.V(4).Info("Creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(glog.V(4).Infof)
	eventBroadcaster.StartRecordingToSink(&corev1.EventSinkImpl{Interface: cl.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: controllerAgentName})

	sharedInformerFactory := informers.NewSharedInformerFactory(intcl, time.Second*30)
	kubeSharedInformerFactory := kubeinformers.NewSharedInformerFactory(cl, time.Second*30)
	return &controller.Context{
		Client:                    cl,
		CMClient:                  intcl,
		Recorder:                  recorder,
		KubeSharedInformerFactory: kubeSharedInformerFactory,
		SharedInformerFactory:     sharedInformerFactory,
		ACMEOptions: controller.ACMEOptions{
			HTTP01SolverImage: opts.ACMEHTTP01SolverImage,
			DNS01Nameservers:  nameservers,
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
			DefaultACMEIssuerChallengeType:     opts.DefaultACMEIssuerChallengeType,
			DefaultACMEIssuerDNS01ProviderName: opts.DefaultACMEIssuerDNS01ProviderName,
		},
	}, kubeCfg, nil
}

func startLeaderElection(opts *options.ControllerOptions, leaderElectionClient kubernetes.Interface, recorder record.EventRecorder, run func(<-chan struct{})) {
	// Identity used to distinguish between multiple controller manager instances
	id, err := os.Hostname()
	if err != nil {
		glog.Fatalf("error getting hostname: %s", err.Error())
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
	leaderelection.RunOrDie(leaderelection.LeaderElectionConfig{
		Lock:          &rl,
		LeaseDuration: opts.LeaderElectionLeaseDuration,
		RenewDeadline: opts.LeaderElectionRenewDeadline,
		RetryPeriod:   opts.LeaderElectionRetryPeriod,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: run,
			OnStoppedLeading: func() {
				glog.Fatalf("leaderelection lost")
			},
		},
	})
}
