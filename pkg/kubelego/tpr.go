package kubelego

import (
	"reflect"
	"time"

	"github.com/munnerz/cert-manager/pkg/apis/certmanager"
	"github.com/munnerz/cert-manager/pkg/ingress"
	"k8s.io/client-go/tools/cache"
)

func (kl *KubeLego) WatchCertificateEvents() {

	kl.Log().Debugf("start watching certificate objects")

	resyncPeriod := 60 * time.Second

	certEventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			addCert := obj.(*certmanager.Certificate)
			if ingress.IgnoreIngress(addIng) != nil {
				return
			}
			kl.Log().Debugf("CREATE certificate/%s/%s", addCert.Namespace, addCert.Name)
			kl.certificateWorkQueue.Add(true)
		},
		DeleteFunc: func(obj interface{}) {
			delCert := obj.(*certmanager.Certificate)
			if ingress.IgnoreIngress(delIng) != nil {
				return
			}
			kl.Log().Debugf("DELETE certificate/%s/%s", delCert.Namespace, delCert.Name)
			kl.certificateWorkQueue.Add(true)
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				upCert := cur.(*certmanager.Certificate)
				if ingress.IgnoreIngress(upIng) != nil {
					return
				}
				kl.Log().Debugf("UPDATE certificate/%s/%s", upCert.Namespace, upCert.Name)
				kl.certificateWorkQueue.Add(true)
			}
		},
	}

	_, controller := cache.NewInformer(
		&cache.ListWatch{
			ListFunc:  ingressListFunc(kl.kubeClient, kl.legoWatchNamespace),
			WatchFunc: ingressWatchFunc(kl.kubeClient, kl.legoWatchNamespace),
		},
		&certmanager.Certificate{},
		resyncPeriod,
		certEventHandler,
	)

	go controller.Run(kl.stopCh)
}
