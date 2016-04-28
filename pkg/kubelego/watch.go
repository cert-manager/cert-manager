package kubelego

import(
	"fmt"
	"reflect"
	"time"

	"k8s.io/kubernetes/pkg/client/cache"
	"k8s.io/kubernetes/pkg/controller/framework"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/watch"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/workqueue"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	"github.com/simonswine/kube-lego/pkg/ingress"
)

func ingressListFunc(c *client.Client, ns string) func(api.ListOptions) (runtime.Object, error) {
	return func(opts api.ListOptions) (runtime.Object, error) {
		return c.Extensions().Ingress(ns).List(opts)
	}
}

func ingressWatchFunc(c *client.Client, ns string) func(options api.ListOptions) (watch.Interface, error) {
	return func(options api.ListOptions) (watch.Interface, error) {
		return c.Extensions().Ingress(ns).Watch(options)
	}
}

func (kl * KubeLego) requestReconfigure(){

}

func (kl * KubeLego) WatchReconfigure(){

	w := workqueue.New()

	go func() {
		kl.waitGroup.Add(1)
		defer kl.waitGroup.Done()
		for j := 0; j < 10; j++ {
			w.Add(fmt.Sprintf("work %d", j))
			time.Sleep(time.Millisecond * 500)
		}
	}()

	// handle worker shutdown
	go func() {
		<- kl.stopCh
		w.ShutDown()
	}()

	go func() {
		kl.waitGroup.Add(1)
		defer kl.waitGroup.Done()
		for {
			item, quit := w.Get()
			if quit {
				return
			}
			kl.Log().Infof("Worker: begin processing %v", item)
			time.Sleep(900 * time.Millisecond)
			kl.Log().Infof("Worker: done processing %v", item)
			w.Done(item)
		}
	}()
}

func (kl * KubeLego) WatchEvents() {

	kl.Log().Infof("start event watcher")

	resyncPeriod := 10 * time.Second

	ingEventHandler := framework.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			addIng := obj.(*extensions.Ingress)
			if ingress.IgnoreIngress(addIng) != nil {
				return
			}
			kl.Log().Infof("CREATE %s/%s", addIng.Namespace, addIng.Name)
		},
		DeleteFunc: func(obj interface{}) {
			delIng := obj.(*extensions.Ingress)
			if ingress.IgnoreIngress(delIng) != nil {
				return
			}
			kl.Log().Infof("DELETE %s/%s", delIng.Namespace, delIng.Name)
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				upIng := cur.(*extensions.Ingress)
				if ingress.IgnoreIngress(upIng) != nil {
					return
				}
				kl.Log().Infof("UPDATE %s/%s", upIng.Namespace, upIng.Name)
			}
		},
	}

	_, controller := framework.NewInformer(
		&cache.ListWatch{
			ListFunc:  ingressListFunc(kl.kubeClient, api.NamespaceAll),
			WatchFunc: ingressWatchFunc(kl.kubeClient, api.NamespaceAll),
		},
		&extensions.Ingress{},
		resyncPeriod,
		ingEventHandler,
	)

	go controller.Run(kl.stopCh)
}