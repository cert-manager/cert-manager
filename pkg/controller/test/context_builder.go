/*
Copyright 2019 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package test

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
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/logs"
)

func init() {
	logs.InitLogs()
	flag.Set("alsologtostderr", fmt.Sprintf("%t", true))
	flag.Lookup("v").Value.Set("4")
}

// Builder is a structure used to construct new Contexts for use during tests.
// Currently, only KubeObjects and CertManagerObjects can be specified.
// These will be auto loaded into the constructed fake Clientsets.
// Call ToContext() to construct a new context using the given values.
type Builder struct {
	T *testing.T

	KubeObjects        []runtime.Object
	CertManagerObjects []runtime.Object
	ExpectedActions    []Action
	StringGenerator    StringGenerator

	stopCh           chan struct{}
	events           []string
	requiredReactors map[string]bool

	*controller.Context
}

func (b *Builder) logf(format string, args ...interface{}) {
	if b.T != nil {
		b.T.Logf(format, args...)
	}
}

func (b *Builder) generateNameReactor(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
	obj := action.(coretesting.CreateAction).GetObject().(metav1.Object)
	genName := obj.GetGenerateName()
	if genName != "" {
		obj.SetName(genName + b.StringGenerator(5))
		return false, obj.(runtime.Object), nil
	}
	return false, obj.(runtime.Object), nil
}

const informerResyncPeriod = time.Millisecond * 500

// ToContext will construct a new context for this builder.
// Subsequent calls to ToContext will return the same Context instance.
func (b *Builder) Start() {
	if b.Context == nil {
		b.Context = &controller.Context{}
	}
	if b.StringGenerator == nil {
		b.StringGenerator = RandStringBytes
	}
	b.requiredReactors = make(map[string]bool)
	b.Client = kubefake.NewSimpleClientset(b.KubeObjects...)
	b.CMClient = cmfake.NewSimpleClientset(b.CertManagerObjects...)
	// create a fake recorder with a buffer of 5.
	// this may need to be increased in future to acomodate tests that
	// produce more than 5 events
	b.Recorder = record.NewFakeRecorder(5)
	// read all events out of the recorder and just log for now
	// TODO: validate logged events
	go func() {
		r, ok := b.Recorder.(*record.FakeRecorder)
		if !ok {
			return
		}

		// exits when r.Events is closed in Finish
		for e := range r.Events {
			b.logf("Event logged: %v", e)
		}
	}()

	b.FakeKubeClient().PrependReactor("create", "*", b.generateNameReactor)
	b.FakeCMClient().PrependReactor("create", "*", b.generateNameReactor)
	b.KubeSharedInformerFactory = kubeinformers.NewSharedInformerFactory(b.Client, informerResyncPeriod)
	b.SharedInformerFactory = informers.NewSharedInformerFactory(b.CMClient, informerResyncPeriod)
	b.stopCh = make(chan struct{})
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

func (b *Builder) EnsureReactorCalled(testName string, fn coretesting.ReactionFunc) coretesting.ReactionFunc {
	b.requiredReactors[testName] = false
	return func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
		handled, ret, err = fn(action)
		if !handled {
			return
		}
		b.requiredReactors[testName] = true
		return
	}
}

func (b *Builder) AllReactorsCalled() error {
	var errs []error
	for n, reactorCalled := range b.requiredReactors {
		if !reactorCalled {
			errs = append(errs, fmt.Errorf("reactor not called: %s", n))
		}
	}
	return utilerrors.NewAggregate(errs)
}

func (b *Builder) AllActionsExecuted() error {
	firedActions := b.FakeCMClient().Actions()
	firedActions = append(firedActions, b.FakeKubeClient().Actions()...)

	var unexpectedActions []coretesting.Action
	var errs []error
	missingActions := make([]Action, len(b.ExpectedActions))
	copy(missingActions, b.ExpectedActions)
	for _, a := range firedActions {
		// skip list and watch actions
		if a.GetVerb() == "list" || a.GetVerb() == "watch" {
			continue
		}
		found := false
		var err error
		for i, expA := range missingActions {
			if expA.Action().GetNamespace() != a.GetNamespace() ||
				expA.Action().GetResource() != a.GetResource() ||
				expA.Action().GetSubresource() != a.GetSubresource() ||
				expA.Action().GetVerb() != a.GetVerb() {
				continue
			}

			err = expA.Matches(a)
			// if this action doesn't match, we record the error and continue
			// as there may be multiple action matchers for the same resource
			if err != nil {
				continue
			}

			missingActions = append(missingActions[:i], missingActions[i+1:]...)
			found = true
			break
		}
		if !found {
			unexpectedActions = append(unexpectedActions, a)

			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, a := range missingActions {
		errs = append(errs, fmt.Errorf("missing action: %v", actionToString(a.Action())))
	}
	for _, a := range unexpectedActions {
		errs = append(errs, fmt.Errorf("unexpected action: %v", actionToString(a)))
	}
	return utilerrors.NewAggregate(errs)
}

func actionToString(a coretesting.Action) string {
	return fmt.Sprintf("%s %q in namespace %s", a.GetVerb(), a.GetResource(), a.GetNamespace())
}

// Stop will signal the informers to stop watching changes
// This method is *not* safe to be called concurrently
func (b *Builder) Stop() {
	if b.stopCh == nil {
		return
	}

	close(b.stopCh)

	if r, ok := b.Recorder.(*record.FakeRecorder); ok {
		close(r.Events)
	}
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
	b.SharedInformerFactory.Start(b.stopCh)
	if err := mustAllSync(b.KubeSharedInformerFactory.WaitForCacheSync(b.stopCh)); err != nil {
		panic("Error waiting for kubeSharedInformerFactory to sync: " + err.Error())
	}
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
