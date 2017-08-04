package issuers

import (
	"fmt"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/munnerz/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/munnerz/cert-manager/pkg/client"
	controllerpkg "github.com/munnerz/cert-manager/pkg/controller"
	"github.com/munnerz/cert-manager/pkg/informers/externalversions"
	cmlisters "github.com/munnerz/cert-manager/pkg/listers/certmanager/v1alpha1"
	"github.com/munnerz/cert-manager/pkg/log"
)

var _ controllerpkg.Constructor = New

var _ controllerpkg.Controller = &controller{}

type controller struct {
	client   kubernetes.Interface
	cmClient client.Interface

	// To allow injection for testing.
	syncHandler func(key string) error

	issuerInformerSynced cache.InformerSynced
	issuerLister         cmlisters.IssuerLister

	secretInformerSynced cache.InformerSynced
	secretLister         corelisters.SecretLister

	queue workqueue.RateLimitingInterface
}

func New(client kubernetes.Interface,
	cmClient client.Interface,
	factory informers.SharedInformerFactory,
	cmFactory externalversions.SharedInformerFactory) (controllerpkg.Controller, error) {

	ctrl := &controller{client: client, cmClient: cmClient}
	ctrl.syncHandler = ctrl.processNextWorkItem
	ctrl.queue = workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "issuers")

	secretsInformer := factory.Core().V1().Secrets()
	issuersInformer := cmFactory.Certmanager().V1alpha1().Issuers()

	issuersInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ctrl.issuerAdded,
		UpdateFunc: ctrl.issuerUpdated,
	})
	ctrl.issuerInformerSynced = issuersInformer.Informer().HasSynced
	ctrl.issuerLister = issuersInformer.Lister()

	secretsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: ctrl.secretDeleted,
	})
	ctrl.secretInformerSynced = secretsInformer.Informer().HasSynced
	ctrl.secretLister = secretsInformer.Lister()

	return ctrl, nil
}

func (c *controller) issuerAdded(obj interface{}) {
	var issuer *v1alpha1.Issuer
	var ok bool
	if issuer, ok = obj.(*v1alpha1.Issuer); !ok {
		runtime.HandleError(fmt.Errorf("expected *Issuer but got %T in work queue", obj))
		return
	}
	var key string
	var err error
	if key, err = cache.DeletionHandlingMetaNamespaceKeyFunc(issuer); err != nil {
		runtime.HandleError(err)
		return
	}
	c.queue.Add(key)
}

func (c *controller) issuerUpdated(prev, obj interface{}) {
	var issuer *v1alpha1.Issuer
	var ok bool
	if issuer, ok = obj.(*v1alpha1.Issuer); !ok {
		runtime.HandleError(fmt.Errorf("expected *Issuer but got %T in work queue", obj))
		return
	}
	if reflect.DeepEqual(prev, obj) {
		return
	}
	var key string
	var err error
	if key, err = cache.DeletionHandlingMetaNamespaceKeyFunc(issuer); err != nil {
		runtime.HandleError(err)
		return
	}
	c.queue.Add(key)
}

func (c *controller) secretDeleted(obj interface{}) {
	var secret *corev1.Secret
	var ok bool
	secret, ok = obj.(*corev1.Secret)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			runtime.HandleError(fmt.Errorf("Couldn't get object from tombstone %#v", obj))
			return
		}
		secret, ok = tombstone.Obj.(*corev1.Secret)
		if !ok {
			runtime.HandleError(fmt.Errorf("Tombstone contained object that is not a Secret %#v", obj))
			return
		}
	}
	log.Printf("TODO: implement watching for deleted secret resources (secret '%s/%s' deleted)", secret.Namespace, secret.Name)
	//c.queue.Add(sa.Namespace)
}

func (c *controller) Run(workers int, stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	log.Printf("Starting control loop")
	// wait for all the informer caches we depend on are synced
	if !cache.WaitForCacheSync(stopCh, c.issuerInformerSynced, c.secretInformerSynced) {
		log.Errorf("error waiting for informer caches to sync")
		return
	}

	for i := 0; i < workers; i++ {
		// TODO (@munnerz): make time.Second duration configurable
		go wait.Until(c.worker, time.Second, stopCh)
	}

	<-stopCh
	log.Printf("shutting down queue as workqueue signalled shutdown")
}

func (c *controller) worker() {
	log.Printf("starting worker")
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
			if err := c.processNextWorkItem(key); err != nil {
				return err
			}
			c.queue.Forget(obj)
			return nil
		}(obj)

		if err != nil {
			log.Printf("requeuing item due to error processing: %s", err.Error())
			c.queue.AddRateLimited(obj)
			continue
		}

		log.Printf("finished processing work item")
	}
	log.Printf("exiting worker loop")
}

func (c *controller) processNextWorkItem(key string) error {
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

	return c.sync(issuer)
}

const (
	ControllerName = "issuers"
)

func init() {
	controllerpkg.SharedFactory().Register(ControllerName, New)
}
