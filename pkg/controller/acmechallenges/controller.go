package acmechallenges

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/golang/glog"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/http"
	"github.com/jetstack/cert-manager/pkg/util"
)

type Controller struct {
	controllerpkg.Context

	helper *controllerpkg.Helper

	// To allow injection for testing.
	syncHandler func(ctx context.Context, key string) error

	challengeLister     cmlisters.ChallengeLister
	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
	secretLister        corelisters.SecretLister

	// ACME challenge solvers are instantiated once at the time of controller
	// construction.
	// This also allows for easy mocking of the different challenge mechanisms.
	dnsSolver  solver
	httpSolver solver

	watchedInformers []cache.InformerSynced
	queue            workqueue.RateLimitingInterface
}

func New(ctx *controllerpkg.Context) *Controller {
	ctrl := &Controller{Context: *ctx}
	ctrl.syncHandler = ctrl.processNextWorkItem

	// exponentially back-off self checks, with a base of 2s and max wait of 20s
	ctrl.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*2, time.Second*20), "challenges")

	challengeInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().Challenges()
	challengeInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
	ctrl.watchedInformers = append(ctrl.watchedInformers, challengeInformer.Informer().HasSynced)
	ctrl.challengeLister = challengeInformer.Lister()

	// issuerInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
	issuerInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().Issuers()
	ctrl.watchedInformers = append(ctrl.watchedInformers, issuerInformer.Informer().HasSynced)
	ctrl.issuerLister = issuerInformer.Lister()

	// clusterIssuerInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
	clusterIssuerInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers()
	ctrl.watchedInformers = append(ctrl.watchedInformers, clusterIssuerInformer.Informer().HasSynced)
	ctrl.clusterIssuerLister = clusterIssuerInformer.Lister()

	secretInformer := ctrl.KubeSharedInformerFactory.Core().V1().Secrets()
	ctrl.watchedInformers = append(ctrl.watchedInformers, secretInformer.Informer().HasSynced)
	ctrl.secretLister = secretInformer.Lister()

	// instantiate listers used by the http01 solver
	podInformer := ctrl.KubeSharedInformerFactory.Core().V1().Pods()
	serviceInformer := ctrl.KubeSharedInformerFactory.Core().V1().Services()
	ingressInformer := ctrl.KubeSharedInformerFactory.Extensions().V1beta1().Ingresses()
	ctrl.watchedInformers = append(ctrl.watchedInformers, podInformer.Informer().HasSynced)
	ctrl.watchedInformers = append(ctrl.watchedInformers, serviceInformer.Informer().HasSynced)
	ctrl.watchedInformers = append(ctrl.watchedInformers, ingressInformer.Informer().HasSynced)

	ctrl.helper = controllerpkg.NewHelper(ctrl.issuerLister, ctrl.clusterIssuerLister)

	ctrl.httpSolver = http.NewSolver(ctx)
	ctrl.dnsSolver = dns.NewSolver(ctx)

	return ctrl
}

func (c *Controller) Run(workers int, stopCh <-chan struct{}) error {
	glog.V(4).Infof("Starting %s control loop", ControllerName)
	// wait for all the informer caches we depend on are synced
	if !cache.WaitForCacheSync(stopCh, c.watchedInformers...) {
		// c.challengeInformerSynced) {
		return fmt.Errorf("error waiting for informer caches to sync")
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		// TODO (@munnerz): make time.Second duration configurable
		go wait.Until(func() {
			defer wg.Done()
			c.worker(stopCh)
		},
			time.Second, stopCh)
	}
	<-stopCh
	glog.V(4).Infof("Shutting down queue as workqueue signaled shutdown")
	c.queue.ShutDown()
	glog.V(4).Infof("Waiting for workers to exit...")
	wg.Wait()
	glog.V(4).Infof("Workers exited.")
	return nil
}

func (c *Controller) worker(stopCh <-chan struct{}) {
	glog.V(4).Infof("Starting %q worker", ControllerName)
	for {
		obj, shutdown := c.queue.Get()
		if shutdown {
			break
		}

		var key string
		err := func(obj interface{}) error {
			defer c.queue.Done(obj)
			var ok bool
			if key, ok = obj.(string); !ok {
				return nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = util.ContextWithStopCh(ctx, stopCh)
			glog.Infof("%s controller: syncing item '%s'", ControllerName, key)
			if err := c.syncHandler(ctx, key); err != nil {
				return err
			}
			c.queue.Forget(obj)
			return nil
		}(obj)

		if err != nil {
			glog.Errorf("%s controller: Re-queuing item %q due to error processing: %s", ControllerName, key, err.Error())
			c.queue.AddRateLimited(obj)
			continue
		}

		glog.Infof("%s controller: Finished processing work item %q", ControllerName, key)
	}
	glog.V(4).Infof("Exiting %q worker loop", ControllerName)
}

func (c *Controller) processNextWorkItem(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	ch, err := c.challengeLister.Challenges(namespace).Get(name)

	if err != nil {
		if k8sErrors.IsNotFound(err) {
			runtime.HandleError(fmt.Errorf("ch '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	return c.Sync(ctx, ch)
}

var keyFunc = controllerpkg.KeyFunc

const (
	ControllerName = "challenges"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) controllerpkg.Interface {
		return New(ctx).Run
	})
}
