package test

import (
	"flag"
	"fmt"
	"reflect"
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
	"github.com/jetstack/cert-manager/pkg/controller"
)

func init() {
	flag.Set("alsologtostderr", fmt.Sprintf("%t", true))
	flag.Lookup("v").Value.Set("4")
}

// Builder is a structure used to construct new Contexts for use during tests.
// Currently, only KubeObjects and CertManagerObjects can be specified.
// These will be auto loaded into the constructed fake Clientsets.
// Call ToContext() to construct a new context using the given values.
type Builder struct {
	KubeObjects        []runtime.Object
	CertManagerObjects []runtime.Object

	stopCh chan struct{}
	events []string

	*controller.Context
}

const informerResyncPeriod = time.Millisecond * 500

// ToContext will construct a new context for this builder.
// Subsequent calls to ToContext will return the same Context instance.
func (b *Builder) Start() {
	if b.Context == nil {
		b.Context = &controller.Context{}
	}

	b.Client = kubefake.NewSimpleClientset(b.KubeObjects...)
	b.CMClient = cmfake.NewSimpleClientset(b.CertManagerObjects...)
	// create a fake recorder with a buffer of 5.
	// this may need to be increased in future to acomodate tests that
	// produce more than 5 events
	b.Recorder = record.NewFakeRecorder(5)

	b.FakeKubeClient().PrependReactor("create", "*", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
		obj := action.(coretesting.CreateAction).GetObject().(metav1.Object)
		genName := obj.GetGenerateName()
		if genName != "" {
			obj.SetName(genName + RandStringBytes(5))
			return false, obj.(runtime.Object), nil
		}
		return false, obj.(runtime.Object), nil
	})
	b.KubeSharedInformerFactory = kubeinformers.NewSharedInformerFactory(b.Client, informerResyncPeriod)
	b.SharedInformerFactory = informers.NewSharedInformerFactory(b.CMClient, informerResyncPeriod)
	b.stopCh = make(chan struct{})
	b.KubeSharedInformerFactory.Start(b.stopCh)
	b.SharedInformerFactory.Start(b.stopCh)
	go b.readEvents()
}

func (b *Builder) FakeKubeClient() *kubefake.Clientset {
	return b.Context.Client.(*kubefake.Clientset)
}

func (b *Builder) FakeKubeInformerFactory() kubeinformers.SharedInformerFactory {
	return b.Context.KubeSharedInformerFactory
}

func (b *Builder) FakeCMClient() *cmfake.Clientset {
	return b.Context.CMClient.(*cmfake.Clientset)
}

func (b *Builder) FakeCMInformerFactory() informers.SharedInformerFactory {
	return b.Context.SharedInformerFactory
}

// Stop will signal the informers to stop watching changes
// This method is *not* safe to be called concurrently
func (b *Builder) Stop() {
	if b.stopCh == nil {
		return
	}

	close(b.stopCh)
}

// WaitForResync will wait for the informer factory informer duration by
// calling time.Sleep. This will ensure that all informer Stores are up to date
// with current information from the fake clients.
func (b *Builder) WaitForResync() {
	// add 100ms here to try and cut down on flakes
	time.Sleep(informerResyncPeriod + time.Millisecond*100)
}

func (b *Builder) Sync() {
	b.KubeSharedInformerFactory.Start(b.stopCh)
	if err := mustAllSync(b.KubeSharedInformerFactory.WaitForCacheSync(b.stopCh)); err != nil {
		panic("Error waiting for kubeSharedInformerFactory to sync: " + err.Error())
	}
	b.SharedInformerFactory.Start(b.stopCh)
	if err := mustAllSync(b.SharedInformerFactory.WaitForCacheSync(b.stopCh)); err != nil {
		panic("Error waiting for SharedInformerFactory to sync: " + err.Error())
	}
}

func (b *Builder) FakeEventRecorder() *record.FakeRecorder {
	return b.Recorder.(*record.FakeRecorder)
}

func (b *Builder) Events() []string {
	return b.events
}

func (b *Builder) readEvents() {
	for {
		select {
		case e := <-b.FakeEventRecorder().Events:
			b.events = append(b.events, e)
		case <-b.stopCh:
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
