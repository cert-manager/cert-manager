package issuers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager"
	"github.com/jetstack-experimental/cert-manager/pkg/client/clientset"
	cminformers "github.com/jetstack-experimental/cert-manager/pkg/client/informers/certmanager/v1alpha1"
	cmlisters "github.com/jetstack-experimental/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack-experimental/cert-manager/pkg/controller"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer"
	"github.com/jetstack-experimental/cert-manager/pkg/util"
)

type Controller struct {
	client        kubernetes.Interface
	cmClient      clientset.Interface
	issuerFactory issuer.Factory
	recorder      record.EventRecorder

	// To allow injection for testing.
	syncHandler func(ctx context.Context, key string) error

	issuerInformerSynced cache.InformerSynced
	issuerLister         cmlisters.IssuerLister

	secretInformerSynced cache.InformerSynced
	secretLister         corelisters.SecretLister

	queue    workqueue.RateLimitingInterface
	workerWg sync.WaitGroup
}

func New(
	issuersInformer cache.SharedIndexInformer,
	secretsInformer cache.SharedIndexInformer,
	cl kubernetes.Interface,
	cmClient clientset.Interface,
	issuerFactory issuer.Factory,
	recorder record.EventRecorder,
) *Controller {
	ctrl := &Controller{client: cl, cmClient: cmClient, issuerFactory: issuerFactory, recorder: recorder}
	ctrl.syncHandler = ctrl.processNextWorkItem
	ctrl.queue = workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "issuers")

	issuersInformer.AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
	ctrl.issuerInformerSynced = issuersInformer.HasSynced
	ctrl.issuerLister = cmlisters.NewIssuerLister(issuersInformer.GetIndexer())

	secretsInformer.AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: ctrl.secretDeleted})
	ctrl.secretInformerSynced = secretsInformer.HasSynced
	ctrl.secretLister = corelisters.NewSecretLister(secretsInformer.GetIndexer())

	return ctrl
}

// TODO: replace with generic handleObjet function (like Navigator)
func (c *Controller) secretDeleted(obj interface{}) {
	var secret *corev1.Secret
	var ok bool
	secret, ok = obj.(*corev1.Secret)
	if !ok {
		runtime.HandleError(fmt.Errorf("Object was not a Secret object %#v", obj))
		return
	}
	issuers, err := c.issuersForSecret(secret)
	if err != nil {
		runtime.HandleError(fmt.Errorf("Error looking up issuers observing Secret: %s/%s", secret.Namespace, secret.Name))
		return
	}
	for _, iss := range issuers {
		key, err := keyFunc(iss)
		if err != nil {
			runtime.HandleError(err)
			continue
		}
		c.queue.Add(key)
	}
}

func (c *Controller) Run(workers int, stopCh <-chan struct{}) error {
	glog.V(4).Infof("Starting %s control loop", ControllerName)
	// wait for all the informer caches we depend on are synced
	if !cache.WaitForCacheSync(stopCh, c.issuerInformerSynced, c.secretInformerSynced) {
		// TODO: replace with Errorf call to glog
		return fmt.Errorf("error waiting for informer caches to sync")
	}

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

	issuer, err := c.issuerLister.Issuers(namespace).Get(name)

	if err != nil {
		if k8sErrors.IsNotFound(err) {
			runtime.HandleError(fmt.Errorf("issuer '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	return c.Sync(ctx, issuer)
}

var keyFunc = controllerpkg.KeyFunc

const (
	ControllerName = "issuers"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) controllerpkg.Interface {
		return New(
			ctx.SharedInformerFactory.InformerFor(
				ctx.Namespace,
				metav1.GroupVersionKind{Group: certmanager.GroupName, Version: "v1alpha1", Kind: "Issuer"},
				cminformers.NewIssuerInformer(
					ctx.CMClient,
					ctx.Namespace,
					time.Second*30,
					cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
				),
			),
			ctx.SharedInformerFactory.InformerFor(
				ctx.Namespace,
				metav1.GroupVersionKind{Version: "v1", Kind: "Secret"},
				coreinformers.NewSecretInformer(
					ctx.Client,
					ctx.Namespace,
					time.Second*30,
					cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
				),
			),
			ctx.Client,
			ctx.CMClient,
			ctx.IssuerFactory,
			ctx.Recorder,
		).Run
	})
}
