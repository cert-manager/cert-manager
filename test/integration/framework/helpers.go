package framework

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"

	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cminformers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
)

func NewEventRecorder(t *testing.T) record.EventRecorder {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(t.Logf)
	return eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: t.Name()})
}

func NewClients(t *testing.T, config *rest.Config) (kubernetes.Interface, informers.SharedInformerFactory, cmclient.Interface, cminformers.SharedInformerFactory) {
	cl, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	factory := informers.NewSharedInformerFactory(cl, 0)
	cmCl, err := cmclient.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	cmFactory := cminformers.NewSharedInformerFactory(cmCl, 0)
	return cl, factory, cmCl, cmFactory
}

func StartInformersAndController(t *testing.T, factory informers.SharedInformerFactory, cmFactory cminformers.SharedInformerFactory, c controllerpkg.Interface) StopFunc {
	stopCh := make(chan struct{})
	go func() {
		factory.Start(stopCh)
		cmFactory.Start(stopCh)
		if err := c.Run(1, stopCh); err != nil {
			t.Fatal(err)
		}
	}()
	return func() {
		close(stopCh)
	}
}
