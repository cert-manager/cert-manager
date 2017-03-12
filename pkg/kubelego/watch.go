package kubelego

import (
	"reflect"
	"time"

	"github.com/jetstack/kube-lego/pkg/ingress"

	k8sMeta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	k8sApi "k8s.io/client-go/pkg/api/v1"
	k8sExtensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

func ingressListFunc(c *kubernetes.Clientset, ns string) func(k8sMeta.ListOptions) (runtime.Object, error) {
	return func(opts k8sMeta.ListOptions) (runtime.Object, error) {
		return c.Extensions().Ingresses(ns).List(opts)
	}
}

func ingressWatchFunc(c *kubernetes.Clientset, ns string) func(options k8sMeta.ListOptions) (watch.Interface, error) {
	return func(options k8sMeta.ListOptions) (watch.Interface, error) {
		return c.Extensions().Ingresses(ns).Watch(options)
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

	resyncPeriod := 60 * time.Second

	ingEventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			addIng := obj.(*k8sExtensions.Ingress)
			if ingress.IgnoreIngress(addIng) != nil {
				return
			}
			kl.Log().Debugf("CREATE ingress/%s/%s", addIng.Namespace, addIng.Name)
			kl.workQueue.Add(true)
		},
		DeleteFunc: func(obj interface{}) {
			delIng := obj.(*k8sExtensions.Ingress)
			if ingress.IgnoreIngress(delIng) != nil {
				return
			}
			kl.Log().Debugf("DELETE ingress/%s/%s", delIng.Namespace, delIng.Name)
			kl.workQueue.Add(true)
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				upIng := cur.(*k8sExtensions.Ingress)
				if ingress.IgnoreIngress(upIng) != nil {
					return
				}
				kl.Log().Debugf("UPDATE ingress/%s/%s", upIng.Namespace, upIng.Name)
				kl.workQueue.Add(true)
			}
		},
	}

	_, controller := cache.NewInformer(
		&cache.ListWatch{
			ListFunc:  ingressListFunc(kl.kubeClient, k8sApi.NamespaceAll),
			WatchFunc: ingressWatchFunc(kl.kubeClient, k8sApi.NamespaceAll),
		},
		&k8sExtensions.Ingress{},
		resyncPeriod,
		ingEventHandler,
	)

	go controller.Run(kl.stopCh)
}
