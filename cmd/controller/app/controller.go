package app

import (
	"fmt"
	"os"
	"sync"

	"github.com/golang/glog"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"

	"github.com/jetstack-experimental/cert-manager/cmd/controller/app/options"
	clientset "github.com/jetstack-experimental/cert-manager/pkg/client/clientset"
	intscheme "github.com/jetstack-experimental/cert-manager/pkg/client/clientset/scheme"
	"github.com/jetstack-experimental/cert-manager/pkg/controller"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer"
	"github.com/jetstack-experimental/cert-manager/pkg/util/kube"
)

const controllerAgentName = "cert-manager-controller"

func Run(opts *options.ControllerOptions, stopCh <-chan struct{}) {
	ctx, kubeCfg, err := buildControllerContext(opts)

	if err != nil {
		glog.Fatalf(err.Error())
	}

	run := func(_ <-chan struct{}) {
		var wg sync.WaitGroup
		var controllers = make(map[string]controller.Interface)
		for n, fn := range controller.Known() {
			controllers[n] = fn(ctx)
		}
		for n, fn := range controllers {
			wg.Add(1)
			go func(n string, fn controller.Interface) {
				defer wg.Done()
				glog.V(4).Infof("Starting %s controller", n)

				err := fn(2, stopCh)

				if err != nil {
					glog.Fatalf("error running %s controller: %s", n, err.Error())
				}
			}(n, fn)
		}
		glog.V(4).Infof("Starting shared informer factory")
		ctx.SharedInformerFactory.Start(stopCh)
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
	kubeCfg, err := KubeConfig(opts.APIServerHost)

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

	// Create event broadcaster
	// Add cert-manager types to the default Kubernetes Scheme so Events can be
	// logged properly
	intscheme.AddToScheme(scheme.Scheme)
	glog.V(4).Info("Creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(glog.V(4).Infof)
	eventBroadcaster.StartRecordingToSink(&corev1.EventSinkImpl{Interface: cl.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: controllerAgentName})

	sharedInformerFactory := kube.NewSharedInformerFactory()
	return &controller.Context{
		Client:                cl,
		CMClient:              intcl,
		Recorder:              recorder,
		SharedInformerFactory: sharedInformerFactory,
		IssuerFactory: issuer.NewFactory(&issuer.Context{
			Client:                cl,
			CMClient:              intcl,
			Recorder:              recorder,
			SharedInformerFactory: sharedInformerFactory,
			Namespace:             opts.Namespace,
		}),
		Namespace: opts.Namespace,
	}, kubeCfg, nil
}

func startLeaderElection(opts *options.ControllerOptions, leaderElectionClient kubernetes.Interface, recorder record.EventRecorder, run func(<-chan struct{})) {
	// Identity used to distinguish between multiple controller manager instances
	id, err := os.Hostname()
	if err != nil {
		glog.Fatalf("error getting hostname: %s", err.Error())
	}

	// Lock required for leader election
	rl := resourcelock.EndpointsLock{
		EndpointsMeta: metav1.ObjectMeta{
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

// KubeConfig will return a rest.Config for communicating with the Kubernetes API server.
// If apiServerHost is specified, a config without authentication that is configured
// to talk to the apiServerHost URL will be returned. Else, the in-cluster config will be loaded,
// and failing this, the config will be loaded from the users local kubeconfig directory
func KubeConfig(apiServerHost string) (*rest.Config, error) {
	var err error
	var cfg *rest.Config

	if len(apiServerHost) > 0 {
		cfg = new(rest.Config)
		cfg.Host = apiServerHost
	} else if cfg, err = rest.InClusterConfig(); err != nil {
		apiCfg, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()

		if err != nil {
			return nil, fmt.Errorf("error loading cluster config: %s", err.Error())
		}

		cfg, err = clientcmd.NewDefaultClientConfig(*apiCfg, &clientcmd.ConfigOverrides{}).ClientConfig()

		if err != nil {
			return nil, fmt.Errorf("error loading cluster client config: %s", err.Error())
		}
	}

	return cfg, nil
}
