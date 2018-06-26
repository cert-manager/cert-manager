package certificates

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	extinformers "k8s.io/client-go/informers/extensions/v1beta1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	extlisters "k8s.io/client-go/listers/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cminformers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions/certmanager/v1alpha1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/pkg/scheduler"
	"github.com/jetstack/cert-manager/pkg/util"
)

type Controller struct {
	client        kubernetes.Interface
	cmClient      clientset.Interface
	issuerFactory issuer.Factory
	recorder      record.EventRecorder

	// To allow injection for testing.
	syncHandler func(ctx context.Context, key string) error

	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
	certificateLister   cmlisters.CertificateLister
	secretLister        corelisters.SecretLister
	ingressLister       extlisters.IngressLister

	queue              workqueue.RateLimitingInterface
	scheduledWorkQueue scheduler.ScheduledWorkQueue
	workerWg           sync.WaitGroup
	syncedFuncs        []cache.InformerSynced
	metrics            *metrics.Metrics
}

// New returns a new Certificates controller. It sets up the informer handler
// functions for all the types it watches.
func New(
	certificatesInformer cminformers.CertificateInformer,
	issuersInformer cminformers.IssuerInformer,
	clusterIssuersInformer cminformers.ClusterIssuerInformer,
	secretsInformer coreinformers.SecretInformer,
	ingressInformer extinformers.IngressInformer,
	podsInformer coreinformers.PodInformer,
	serviceInformer coreinformers.ServiceInformer,
	client kubernetes.Interface,
	cmClient clientset.Interface,
	issuerFactory issuer.Factory,
	recorder record.EventRecorder,
	metrics *metrics.Metrics,
) *Controller {

	ctrl := &Controller{client: client, cmClient: cmClient, issuerFactory: issuerFactory, recorder: recorder, metrics: metrics}

	ctrl.syncHandler = ctrl.processNextWorkItem
	ctrl.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*2, time.Minute*1), "certificates")
	// Create a scheduled work queue that calls the ctrl.queue.Add method for
	// each object in the queue. This is used to schedule re-checks of
	// Certificate resources when they get near to expiry
	ctrl.scheduledWorkQueue = scheduler.NewScheduledWorkQueue(ctrl.queue.AddRateLimited)

	certificatesInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
	ctrl.certificateLister = certificatesInformer.Lister()
	ctrl.syncedFuncs = append(ctrl.syncedFuncs, certificatesInformer.Informer().HasSynced)

	ctrl.issuerLister = issuersInformer.Lister()
	ctrl.syncedFuncs = append(ctrl.syncedFuncs, issuersInformer.Informer().HasSynced)

	// clusterIssuersInformer may be nil if cert-manager is scoped to a single
	// namespace
	if clusterIssuersInformer != nil {
		ctrl.clusterIssuerLister = clusterIssuersInformer.Lister()
		ctrl.syncedFuncs = append(ctrl.syncedFuncs, clusterIssuersInformer.Informer().HasSynced)
	}

	secretsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: ctrl.secretDeleted,
	})
	ctrl.secretLister = secretsInformer.Lister()
	ctrl.syncedFuncs = append(ctrl.syncedFuncs, secretsInformer.Informer().HasSynced)

	ctrl.ingressLister = ingressInformer.Lister()
	ctrl.syncedFuncs = append(ctrl.syncedFuncs, ingressInformer.Informer().HasSynced)

	// We also add pod and service informers to the list of informers to sync.
	// They are not actually used directly by the Certificates controller,
	// however the ACME HTTP challenge solver *does* require a Pod and Secret
	// lister, and due to the way the instantiation of issuers is performed it
	// is far more performant to perform the sync here.
	// We should consider moving this into pkg/issuer/acme at some point, some how.
	ctrl.syncedFuncs = append(ctrl.syncedFuncs, podsInformer.Informer().HasSynced)
	ctrl.syncedFuncs = append(ctrl.syncedFuncs, serviceInformer.Informer().HasSynced)

	return ctrl
}

// TODO: replace with generic handleObjet function (like Navigator)
func (c *Controller) secretDeleted(obj interface{}) {
	var secret *corev1.Secret
	var ok bool
	secret, ok = obj.(*corev1.Secret)
	if !ok {
		runtime.HandleError(fmt.Errorf("Object is not a Secret object %#v", obj))
		return
	}
	crts, err := c.certificatesForSecret(secret)
	if err != nil {
		runtime.HandleError(fmt.Errorf("Error looking up Certificates observing Secret: %s/%s", secret.Namespace, secret.Name))
		return
	}
	for _, crt := range crts {
		key, err := keyFunc(crt)
		if err != nil {
			runtime.HandleError(err)
			continue
		}
		c.queue.AddRateLimited(key)
	}
}

func (c *Controller) Run(workers int, stopCh <-chan struct{}) error {
	glog.V(4).Infof("Starting %s control loop", ControllerName)
	// wait for all the informer caches we depend to sync
	if !cache.WaitForCacheSync(stopCh, c.syncedFuncs...) {
		return fmt.Errorf("error waiting for informer caches to sync")
	}

	glog.V(4).Infof("Synced all caches for %s control loop", ControllerName)

	for i := 0; i < workers; i++ {
		c.workerWg.Add(1)
		// TODO (@munnerz): make time.Second duration configurable
		go wait.Until(func() { c.worker(stopCh) }, time.Second, stopCh)
	}
	<-stopCh
	glog.V(4).Infof("Shutting down queue as workqueue signaled shutdown")
	c.queue.ShutDown()
	glog.V(4).Infof("Waiting for workers to exit...")
	c.workerWg.Wait()
	glog.V(4).Infof("Workers exited.")
	return nil
}

func (c *Controller) worker(stopCh <-chan struct{}) {
	defer c.workerWg.Done()
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

	crt, err := c.certificateLister.Certificates(namespace).Get(name)

	if err != nil {
		if k8sErrors.IsNotFound(err) {
			c.scheduledWorkQueue.Forget(key)
			runtime.HandleError(fmt.Errorf("certificate '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	return c.Sync(ctx, crt)
}

var keyFunc = controllerpkg.KeyFunc

const (
	ControllerName = "certificates"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) controllerpkg.Interface {
		return New(
			ctx.SharedInformerFactory.Certmanager().V1alpha1().Certificates(),
			ctx.SharedInformerFactory.Certmanager().V1alpha1().Issuers(),
			ctx.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers(),
			ctx.KubeSharedInformerFactory.Core().V1().Secrets(),
			ctx.KubeSharedInformerFactory.Extensions().V1beta1().Ingresses(),
			ctx.KubeSharedInformerFactory.Core().V1().Pods(),
			ctx.KubeSharedInformerFactory.Core().V1().Services(),
			ctx.Client,
			ctx.CMClient,
			ctx.IssuerFactory,
			ctx.Recorder,
			ctx.Metrics,
		).Run
	})
}
