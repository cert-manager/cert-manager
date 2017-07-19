package ingress

import (
	extensions "k8s.io/api/extensions/v1beta1"
	"k8s.io/client-go/util/workqueue"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
)

type Controller struct {
	*controller.Base
}

func New(ctx controller.Context) (*Controller, error) {
	ctrl := &Controller{}
	base := &controller.Base{
		Context: ctx,
		Queue:   workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		Worker:  ctrl.processNextWorkItem,
	}
	ctrl.Base = base

	// Start watching for changes to Ingress resources
	ctrl.AddHandler(ctx.InformerFactory.Extensions().V1beta1().Ingresses().Informer())
	ctrl.AddHandler(ctx.CertManagerInformerFactory.Certmanager().V1alpha1().Certificates().Informer())

	return ctrl, nil
}

func (c *Controller) processNextWorkItem() bool {
	obj, shutdown := c.Queue.Get()
	if shutdown {
		return false
	}
	defer c.Queue.Done(obj)

	switch v := obj.(type) {
	case *extensions.Ingress:
		if err := c.sync(v); err != nil {
			c.Context.Logger.Errorf("error processing work item: %s", err.Error())
			c.Queue.AddRateLimited(obj)
		} else {
			c.Queue.Forget(obj)
		}
	case *v1alpha1.Certificate:
		// TODO (@munnerz): lookup ingress for this certificate resource, and
		// add it the the workqueue in order to ensure the ingress and
		// certificate resource are in sync.
	default:
		c.Context.Logger.Errorf("unexpected resource type (%T) in work queue", obj)
	}

	return true
}
