package certificates

import (
	"time"

	api "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/juju/ratelimit"
)

func New(ctx controller.Context) controller.Controller {
	return controller.Controller{
		Context: &ctx,
		Queue: workqueue.NewRateLimitingQueue(
			workqueue.NewMaxOfRateLimiter(
				workqueue.NewItemExponentialFailureRateLimiter(15*time.Second, time.Minute),
				// 10 qps, 100 bucket size.  This is only for retry speed and its only the overall factor (not per item)
				&workqueue.BucketRateLimiter{Bucket: ratelimit.NewBucketWithRate(float64(10), int64(100))},
			),
		),
		Worker: processNextWorkItem,
		Informers: []cache.SharedIndexInformer{
			ctx.CertManagerInformerFactory.Certmanager().V1alpha1().Certificates().Informer(),
			ctx.InformerFactory.Core().V1().Secrets().Informer(),
		},
	}
}

func processNextWorkItem(ctx controller.Context, obj interface{}) error {
	ctx.Logger.Printf("obj of type %T", obj)
	switch v := obj.(type) {
	case *v1alpha1.Certificate:
		if err := sync(&ctx, v); err != nil {
			return err
		}
	case *api.Secret:
	default:
		ctx.Logger.Errorf("unexpected resource type (%T) in work queue", obj)
	}
	return nil
}
