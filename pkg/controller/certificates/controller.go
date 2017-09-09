package certificates

import (
	"fmt"
	"sync"
	"time"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	extv1beta1 "k8s.io/api/extensions/v1beta1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	extinformers "k8s.io/client-go/informers/extensions/v1beta1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	extlisters "k8s.io/client-go/listers/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager"
	"github.com/jetstack-experimental/cert-manager/pkg/client/clientset"
	cminformers "github.com/jetstack-experimental/cert-manager/pkg/client/informers/certmanager/v1alpha1"
	cmlisters "github.com/jetstack-experimental/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack-experimental/cert-manager/pkg/controller"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer"
	"github.com/jetstack-experimental/cert-manager/pkg/scheduler"
)

type Controller struct {
	client        kubernetes.Interface
	cmClient      clientset.Interface
	issuerFactory issuer.Factory

	// To allow injection for testing.
	syncHandler func(key string) error

	issuerInformerSynced cache.InformerSynced
	issuerLister         cmlisters.IssuerLister

	certificateInformerSynced cache.InformerSynced
	certificateLister         cmlisters.CertificateLister

	secretInformerSynced cache.InformerSynced
	secretLister         corelisters.SecretLister

	ingressInformerSynced cache.InformerSynced
	ingressLister         extlisters.IngressLister

	queue              workqueue.RateLimitingInterface
	scheduledWorkQueue scheduler.ScheduledWorkQueue
	workerWg           sync.WaitGroup
}

// New returns a new Certificates controller. It sets up the informer handler
// functions for all the types it watches.
func New(
	certificatesInformer cache.SharedIndexInformer,
	secretsInformer cache.SharedIndexInformer,
	ingressInformer cache.SharedIndexInformer,
	client kubernetes.Interface,
	cmClient clientset.Interface,
	issuerFactory issuer.Factory,
) *Controller {
	ctrl := &Controller{client: client, cmClient: cmClient, issuerFactory: issuerFactory}
	ctrl.syncHandler = ctrl.processNextWorkItem
	ctrl.queue = workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "certificates")
	// Create a scheduled work queue that calls the ctrl.queue.Add method for
	// each object in the queue. This is used to schedule re-checks of
	// Certificate resources when they get near to expiry
	ctrl.scheduledWorkQueue = scheduler.NewScheduledWorkQueue(ctrl.queue.Add)

	certificatesInformer.AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
	ctrl.certificateInformerSynced = certificatesInformer.HasSynced
	ctrl.certificateLister = cmlisters.NewCertificateLister(certificatesInformer.GetIndexer())

	ctrl.issuerInformerSynced = issuersInformer.HasSynced
	ctrl.issuerLister = cmlisters.NewIssuerLister(issuersInformer.GetIndexer())

	secretsInformer.AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: ctrl.secretDeleted})
	ctrl.secretInformerSynced = secretsInformer.HasSynced
	ctrl.secretLister = corelisters.NewSecretLister(secretsInformer.GetIndexer())

	ingressInformer.AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: ctrl.ingressDeleted})
	ctrl.ingressInformerSynced = ingressInformer.HasSynced
	ctrl.ingressLister = extlisters.NewIngressLister(ingressInformer.GetIndexer())

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
		c.queue.Add(key)
	}
}

func (c *Controller) ingressDeleted(obj interface{}) {
	ingress, ok := obj.(*extv1beta1.Ingress)
	if !ok {
		runtime.HandleError(fmt.Errorf("Object is not an Ingress object %#v", obj))
		return
	}
	crts, err := c.certificatesForIngress(ingress)
	if err != nil {
		runtime.HandleError(fmt.Errorf("Error looking up certificates observing Ingress: %s/%s", ingress.Namespace, ingress.Name))
		return
	}
	for _, crt := range crts {
		key, err := keyFunc(crt)
		if err != nil {
			runtime.HandleError(err)
			continue
		}
		c.queue.Add(key)
	}
}

func (c *Controller) Run(workers int, stopCh <-chan struct{}) error {
	glog.V(4).Infof("Starting %s control loop", ControllerName)
	// wait for all the informer caches we depend to sync
	if !cache.WaitForCacheSync(stopCh,
		c.secretInformerSynced,
		c.certificateInformerSynced,
		c.ingressInformerSynced) {
		return fmt.Errorf("error waiting for informer caches to sync")
	}

	glog.V(4).Infof("Synced all caches for %s control loop", ControllerName)

	for i := 0; i < workers; i++ {
		c.workerWg.Add(1)
		// TODO (@munnerz): make time.Second duration configurable
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
	glog.V(4).Infof("Shutting down queue as workqueue signaled shutdown")
	c.queue.ShutDown()
	glog.V(4).Infof("Waiting for workers to exit...")
	c.workerWg.Wait()
	glog.V(4).Infof("Workers exited.")
	return nil
}

func (c *Controller) worker() {
	defer c.workerWg.Done()
	glog.V(4).Infof("Starting %s worker", ControllerName)
	for {
		obj, shutdown := c.queue.Get()
		if shutdown {
			break
		}

		err := func(obj interface{}) error {
			defer c.queue.Done(obj)
			var key string
			var ok bool
			if key, ok = obj.(string); !ok {
				runtime.HandleError(fmt.Errorf("expected string in workqueue but got %T", obj))
				return nil
			}
			if err := c.syncHandler(key); err != nil {
				return err
			}
			c.queue.Forget(obj)
			return nil
		}(obj)

		if err != nil {
			glog.V(2).Infof("Requeuing object due to error processing: %s", err.Error())
			c.queue.AddRateLimited(obj)
			continue
		}

		glog.V(4).Infof("Finished processing work item")
	}
	glog.V(4).Infof("Exiting %s worker loop", ControllerName)
}

func (c *Controller) processNextWorkItem(key string) error {
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

	return c.Sync(crt)
}

var keyFunc = controllerpkg.KeyFunc

const (
	ControllerName = "certificates"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) controllerpkg.Interface {
		return New(
			ctx.SharedInformerFactory.InformerFor(
				ctx.Namespace,
				metav1.GroupVersionKind{Group: certmanager.GroupName, Version: "v1alpha1", Kind: "Certificate"},
				cminformers.NewCertificateInformer(
					ctx.CMClient,
					ctx.Namespace,
					time.Second*30,
					cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
				),
			),
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
			ctx.SharedInformerFactory.InformerFor(
				ctx.Namespace,
				metav1.GroupVersionKind{Group: "extensions", Version: "v1beta1", Kind: "Ingress"},
				extinformers.NewIngressInformer(
					ctx.Client,
					ctx.Namespace,
					time.Second*30,
					cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
				),
			),
			ctx.Client,
			ctx.CMClient,
			ctx.IssuerFactory,
		).Run
	})
}
