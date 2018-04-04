package unit

import (
	"flag"
	"fmt"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	kubeinformers "k8s.io/client-go/informers"
	kubefake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"

	cmfake "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/fake"
	informers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
)

func init() {
	flag.Set("alsologtostderr", fmt.Sprintf("%t", true))
	flag.Lookup("v").Value.Set("4")
}

const informerResyncPeriod = time.Millisecond * 500

type Fixture struct {
	T                  *testing.T
	KubeObjects        []runtime.Object
	CertManagerObjects []runtime.Object

	kubeClient *kubefake.Clientset
	cmClient   *cmfake.Clientset
	recorder   *record.FakeRecorder

	stopCh                    chan struct{}
	kubeSharedInformerFactory kubeinformers.SharedInformerFactory
	cmSharedInformerFactory   informers.SharedInformerFactory
	events                    []string
}

func (s *Fixture) KubeClient() *kubefake.Clientset {
	return s.kubeClient
}

func (s *Fixture) KubeInformerFactory() kubeinformers.SharedInformerFactory {
	return s.kubeSharedInformerFactory
}

func (s *Fixture) CertManagerClient() *cmfake.Clientset {
	return s.cmClient
}

func (s *Fixture) CertManagerInformerFactory() informers.SharedInformerFactory {
	return s.cmSharedInformerFactory
}

func (s *Fixture) Start() {
	s.kubeClient = kubefake.NewSimpleClientset(s.KubeObjects...)
	s.cmClient = cmfake.NewSimpleClientset(s.CertManagerObjects...)
	// create a fake recorder with a buffer of 5.
	// this may need to be increased in future to acomodate tests that
	// produce more than 5 events
	s.recorder = record.NewFakeRecorder(5)

	s.kubeClient.PrependReactor("create", "*", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
		obj := action.(coretesting.CreateAction).GetObject().(metav1.Object)
		genName := obj.GetGenerateName()
		if genName != "" {
			obj.SetName(genName + RandStringBytes(5))
			return false, obj.(runtime.Object), nil
		}
		return false, obj.(runtime.Object), nil
	})
	s.kubeSharedInformerFactory = kubeinformers.NewSharedInformerFactory(s.kubeClient, informerResyncPeriod)
	s.cmSharedInformerFactory = informers.NewSharedInformerFactory(s.cmClient, informerResyncPeriod)
	s.stopCh = make(chan struct{})
	s.kubeSharedInformerFactory.Start(s.stopCh)
	s.cmSharedInformerFactory.Start(s.stopCh)
}

// Stop will signal the informers to stop watching changes
// This method is *not* safe to be called concurrently
func (s *Fixture) Stop() {
	if s.stopCh == nil {
		return
	}

	close(s.stopCh)
	s.stopCh = nil
}

// WaitForResync will wait for the informer factory informer duration by
// calling time.Sleep. This will ensure that all informer Stores are up to date
// with current information from the fake clients.
func (s *Fixture) WaitForResync() {
	// add 100ms here to try and cut down on flakes
	time.Sleep(informerResyncPeriod + time.Millisecond*100)
}

func (s *Fixture) Sync() {
	s.kubeSharedInformerFactory.Start(s.stopCh)
	if err := mustAllSync(s.kubeSharedInformerFactory.WaitForCacheSync(s.stopCh)); err != nil {
		s.T.Fatalf("Error waiting for kubeSharedInformerFactory to sync: %v", err)
	}
	s.cmSharedInformerFactory.Start(s.stopCh)
	if err := mustAllSync(s.cmSharedInformerFactory.WaitForCacheSync(s.stopCh)); err != nil {
		s.T.Fatalf("Error waiting for cmSharedInformerFactory to sync: %v", err)
	}
}

func (s *Fixture) EventRecorder() *record.FakeRecorder {
	return s.recorder
}

func (s *Fixture) Events() []string {
	return s.events
}

func (s *Fixture) readEvents() {
	for {
		select {
		case e := <-s.recorder.Events:
			s.events = append(s.events, e)
		case <-s.stopCh:
			return
		}
	}
}

func mustAllSync(in map[reflect.Type]bool) error {
	var errs []error
	for t, started := range in {
		if !started {
			errs = append(errs, fmt.Errorf("informer for %v not synced", t))
		}
	}
	return utilerrors.NewAggregate(errs)
}
