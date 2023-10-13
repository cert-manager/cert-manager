package metrics

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/metrics"
)

const (
	// ControllerName is the string used to refer to this controller
	// when enabling or disabling it from command line flags.
	ControllerName = "certificates-request-metrics"
)

// controllerWrapper wraps the `controller` structure to make it implement
// the controllerpkg.queueingController interface
type controllerWrapper struct {
	*controller
}

// This controller is synced on all Certificate 'create', 'update', and
// 'delete' events which will update the metrics for that Certificate.
type controller struct {
	certificateRequestLister cmlisters.CertificateRequestLister

	metrics *metrics.Metrics
}

func NewController(ctx *controllerpkg.Context) (*controller, workqueue.RateLimitingInterface, []cache.InformerSynced) {
	// create a queue used to queue up items to be processed
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*1, time.Second*30), ControllerName)

	certificateRequestInformer := ctx.SharedInformerFactory.Certmanager().V1().CertificateRequests()
	certificateRequestInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: queue})

	// build a list of InformerSynced functions that will be returned by the
	// Register method.  the controller will only begin processing items once all
	// of these informers have synced.
	mustSync := []cache.InformerSynced{
		certificateRequestInformer.Informer().HasSynced,
	}

	return &controller{
		certificateRequestLister: certificateRequestInformer.Lister(),
		metrics:                  ctx.Metrics,
	}, queue, mustSync
}

func (c *controller) ProcessItem(ctx context.Context, key string) error {
	// Set context deadline for full sync in 10 seconds
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil
	}

	// Handle CertificateRequest metrics
	cr, err := c.certificateRequestLister.CertificateRequests(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		c.metrics.RemoveCertificateRequest(key)
	} else if err == nil {
		c.metrics.UpdateCertificateRequest(ctx, cr)
	}

	return nil
}

func (c *controllerWrapper) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	ctrl, queue, mustSync := NewController(ctx)
	c.controller = ctrl

	return queue, mustSync, nil
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&controllerWrapper{}).
			Complete()
	})
}
