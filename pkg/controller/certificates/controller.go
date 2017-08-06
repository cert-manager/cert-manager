package certificates

import (
	"fmt"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	extv1beta1 "k8s.io/api/extensions/v1beta1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	extlisters "k8s.io/client-go/listers/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/munnerz/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/munnerz/cert-manager/pkg/client"
	controllerpkg "github.com/munnerz/cert-manager/pkg/controller"
	"github.com/munnerz/cert-manager/pkg/informers/externalversions"
	cmlisters "github.com/munnerz/cert-manager/pkg/listers/certmanager/v1alpha1"
	"github.com/munnerz/cert-manager/pkg/log"
	"github.com/munnerz/cert-manager/pkg/scheduler"
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

	certificateInformerSynced cache.InformerSynced
	certificateLister         cmlisters.CertificateLister

	secretInformerSynced cache.InformerSynced
	secretLister         corelisters.SecretLister

	ingressInformerSynced cache.InformerSynced
	ingressLister         extlisters.IngressLister

	queue              workqueue.RateLimitingInterface
	scheduledWorkQueue *scheduler.ScheduledWorkQueue
}

// New returns a new Certificates controller. It sets up the informer handler
// functions for all the types it watches.
func New(client kubernetes.Interface,
	cmClient client.Interface,
	factory informers.SharedInformerFactory,
	cmFactory externalversions.SharedInformerFactory) (controllerpkg.Controller, error) {

	ctrl := &controller{client: client, cmClient: cmClient}
	ctrl.syncHandler = ctrl.processNextWorkItem
	ctrl.queue = workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "certificates")
	// Create a scheduled work queue that calls the ctrl.queue.Add method for
	// each object in the queue. This is used to schedule re-checks of
	// Certificate resources when they get near to expiry
	ctrl.scheduledWorkQueue = scheduler.NewScheduledWorkQueue(ctrl.queue.Add)

	secretsInformer := factory.Core().V1().Secrets()
	ingressInformer := factory.Extensions().V1beta1().Ingresses()
	certificatesInformer := cmFactory.Certmanager().V1alpha1().Certificates()
	issuersInformer := cmFactory.Certmanager().V1alpha1().Issuers()

	certificatesInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    ctrl.certificateAdded,
		UpdateFunc: ctrl.certificateUpdated,
		DeleteFunc: ctrl.certificateDeleted,
	}, time.Minute*5)
	ctrl.certificateInformerSynced = certificatesInformer.Informer().HasSynced
	ctrl.certificateLister = certificatesInformer.Lister()

	secretsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: ctrl.secretDeleted,
	})
	ctrl.secretInformerSynced = secretsInformer.Informer().HasSynced
	ctrl.secretLister = secretsInformer.Lister()

	ctrl.issuerInformerSynced = issuersInformer.Informer().HasSynced
	ctrl.issuerLister = issuersInformer.Lister()

	ingressInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: ctrl.ingressDeleted,
	})
	ctrl.ingressInformerSynced = ingressInformer.Informer().HasSynced
	ctrl.ingressLister = ingressInformer.Lister()

	return ctrl, nil
}

func (c *controller) certificateAdded(obj interface{}) {
	var certificate *v1alpha1.Certificate
	var ok bool
	if certificate, ok = obj.(*v1alpha1.Certificate); !ok {
		runtime.HandleError(fmt.Errorf("expected *Certificate but got %T in work queue", obj))
		return
	}
	c.enqueueCertificate(certificate)
}

func (c *controller) enqueueCertificate(crt *v1alpha1.Certificate) {
	var key string
	var err error
	if key, err = keyFunc(crt); err != nil {
		runtime.HandleError(err)
		return
	}
	c.queue.Add(key)
}

func (c *controller) certificateUpdated(prev, obj interface{}) {
	var certificate *v1alpha1.Certificate
	var ok bool
	if certificate, ok = obj.(*v1alpha1.Certificate); !ok {
		runtime.HandleError(fmt.Errorf("expected *Certificate but got %T in work queue", obj))
		return
	}
	if reflect.DeepEqual(prev, obj) {
		return
	}
	c.enqueueCertificate(certificate)
}

func (c *controller) certificateDeleted(obj interface{}) {
	certificate, ok := obj.(*v1alpha1.Certificate)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			runtime.HandleError(fmt.Errorf("Couldn't get object from tombstone %#v", obj))
			return
		}
		certificate, ok = tombstone.Obj.(*v1alpha1.Certificate)
		if !ok {
			runtime.HandleError(fmt.Errorf("Tombstone contained object that is not a Secret %#v", obj))
			return
		}
	}
	c.enqueueCertificate(certificate)
}

func (c *controller) secretDeleted(obj interface{}) {
	secret, ok := obj.(*corev1.Secret)
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
	crts, err := c.certificatesForSecret(secret)
	if err != nil {
		runtime.HandleError(fmt.Errorf("Error looking up certificates observing Secret: %s/%s", secret.Namespace, secret.Name))
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

func (c *controller) ingressDeleted(obj interface{}) {
	ingress, ok := obj.(*extv1beta1.Ingress)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			runtime.HandleError(fmt.Errorf("Couldn't get object from tombstone %#v", obj))
			return
		}
		ingress, ok = tombstone.Obj.(*extv1beta1.Ingress)
		if !ok {
			runtime.HandleError(fmt.Errorf("Tombstone contained object that is not an Ingress %#v", obj))
			return
		}
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

func (c *controller) Run(workers int, stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	log.Printf("Starting control loop")
	// wait for all the informer caches we depend on are synced
	if !cache.WaitForCacheSync(stopCh,
		c.issuerInformerSynced,
		c.secretInformerSynced,
		c.certificateInformerSynced,
		c.ingressInformerSynced) {
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
			if err := c.syncHandler(key); err != nil {
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

	crt, err := c.certificateLister.Certificates(namespace).Get(name)

	if err != nil {
		if k8sErrors.IsNotFound(err) {
			c.scheduledWorkQueue.Forget(key)
			runtime.HandleError(fmt.Errorf("certificate '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	return c.sync(crt)
}

var keyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc

const (
	ControllerName = "certificates"
)

func init() {
	controllerpkg.SharedFactory().Register(ControllerName, New)
}
