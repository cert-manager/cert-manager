package issuers

import (
	"time"

	"github.com/juju/ratelimit"
	api "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/munnerz/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/munnerz/cert-manager/pkg/controller"
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
			ctx.CertManagerInformerFactory.Certmanager().V1alpha1().Issuers().Informer(),
			ctx.InformerFactory.Core().V1().Secrets().Informer(),
		},
	}
}

func processNextWorkItem(ctx controller.Context, obj interface{}) error {
	switch v := obj.(type) {
	case *v1alpha1.Issuer:
		if err := sync(&ctx, v.Namespace, v.Name); err != nil {
			return err
		}
	case *api.Secret:
		ctx.Logger.Printf("got secret %s/%s, nothing implemented to handle yet", v.Namespace, v.Name)
	default:
		ctx.Logger.Errorf("unexpected resource type (%T) in work queue", obj)
	}

	return nil
}
