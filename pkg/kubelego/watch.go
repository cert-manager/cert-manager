package kubelego

import (
	"reflect"
	"time"

	"github.com/jetstack/kube-lego/pkg/ingress"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/client/cache"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/controller/framework"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/workqueue"
	"k8s.io/kubernetes/pkg/watch"
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

func (kl *KubeLego) requestReconfigure() {
	kl.workQueue.Add(true)
}

func (kl *KubeLego) WatchReconfigure() {

	kl.workQueue = workqueue.New()

	// handle worker shutdown
	go func() {
		<-kl.stopCh
		kl.workQueue.ShutDown()
	}()

	go func() {
		kl.waitGroup.Add(1)
		defer kl.waitGroup.Done()
		for {
			item, quit := kl.workQueue.Get()
			if quit {
				return
			}
			kl.Log().Debugf("worker: begin processing %v", item)
			kl.Reconfigure()
			kl.Log().Debugf("worker: done processing %v", item)
			kl.workQueue.Done(item)
		}
	}()
}

func (kl *KubeLego) WatchEvents() {

	kl.Log().Debugf("start watching ingress objects")

	resyncPeriod := 10 * time.Second

	ingEventHandler := framework.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			addIng := obj.(*extensions.Ingress)
			if ingress.IgnoreIngress(addIng) != nil {
				return
			}
			kl.Log().Debugf("CREATE ingress/%s/%s", addIng.Namespace, addIng.Name)
			kl.workQueue.Add(true)
		},
		DeleteFunc: func(obj interface{}) {
			delIng := obj.(*extensions.Ingress)
			if ingress.IgnoreIngress(delIng) != nil {
				return
			}
			kl.Log().Debugf("DELETE ingress/%s/%s", delIng.Namespace, delIng.Name)
			kl.workQueue.Add(true)
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				upIng := cur.(*extensions.Ingress)
				if ingress.IgnoreIngress(upIng) != nil {
					return
				}
				kl.Log().Debugf("UPDATE ingress/%s/%s", upIng.Namespace, upIng.Name)
				kl.workQueue.Add(true)
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
