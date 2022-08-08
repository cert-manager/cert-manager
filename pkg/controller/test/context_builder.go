/*
Copyright 2020 The cert-manager Authors.

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
	"context"
	"flag"
	"fmt"
	"reflect"
	"testing"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	kubeinformers "k8s.io/client-go/informers"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/clock"
	fakeclock "k8s.io/utils/clock/testing"
	gwfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
	gwinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmfake "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	informers "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	"github.com/cert-manager/cert-manager/pkg/util"
	discoveryfake "github.com/cert-manager/cert-manager/test/unit/discovery"
)

func init() {
	logs.InitLogs(nil)
	_ = flag.Set("alsologtostderr", fmt.Sprintf("%t", true))
	_ = flag.Lookup("v").Value.Set("4")
}

// Builder is a structure used to construct new Contexts for use during tests.
// Currently, only KubeObjects, CertManagerObjects and GWObjects can be
// specified. These will be auto loaded into the constructed fake Clientsets.
// Call ToContext() to construct a new context using the given values.
type Builder struct {
	T *testing.T

	KubeObjects        []runtime.Object
	CertManagerObjects []runtime.Object
	GWObjects          []runtime.Object
	ExpectedActions    []Action
	ExpectedEvents     []string
	StringGenerator    StringGenerator

	// Clock will be the Clock set on the controller context.
	// If not specified, the RealClock will be used.
	Clock *fakeclock.FakeClock

	// CheckFn is a custom check function that will be executed when the
	// CheckAndFinish method is called on the builder, after all other checks.
	// It will be passed a reference to the Builder in order to access state,
	// as well as a list of all the arguments passed to the CheckAndFinish
	// function (typically the list of return arguments from the function under
	// test).
	CheckFn func(*Builder, ...interface{})

	stopCh              chan struct{}
	requiredReactors    map[string]bool
	additionalSyncFuncs []cache.InformerSynced

	*controller.Context
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

const informerResyncPeriod = time.Second

// Init will construct a new context for this builder and set default values
// for any unset fields.
func (b *Builder) Init() {
	if b.Context == nil {
		b.Context = &controller.Context{
			RootContext: context.Background(),
		}
	}
	if b.StringGenerator == nil {
		b.StringGenerator = RandStringBytes
	}
	b.requiredReactors = make(map[string]bool)
	b.Client = kubefake.NewSimpleClientset(b.KubeObjects...)
	b.CMClient = cmfake.NewSimpleClientset(b.CertManagerObjects...)
	b.GWClient = gwfake.NewSimpleClientset(b.GWObjects...)
	b.DiscoveryClient = discoveryfake.NewDiscovery().WithServerResourcesForGroupVersion(func(groupVersion string) (*metav1.APIResourceList, error) {
		if groupVersion == networkingv1.SchemeGroupVersion.String() {
			return &metav1.APIResourceList{
				TypeMeta:     metav1.TypeMeta{},
				GroupVersion: networkingv1.SchemeGroupVersion.String(),
				APIResources: []metav1.APIResource{
					{
						Name:               "ingresses",
						SingularName:       "Ingress",
						Namespaced:         true,
						Group:              networkingv1.GroupName,
						Version:            networkingv1.SchemeGroupVersion.Version,
						Kind:               networkingv1.SchemeGroupVersion.WithKind("Ingress").Kind,
						Verbs:              metav1.Verbs{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"},
						ShortNames:         []string{"ing"},
						Categories:         []string{"all"},
						StorageVersionHash: "testing",
					},
				},
			}, nil
		}
		return &metav1.APIResourceList{}, nil
	})
	b.Recorder = new(FakeRecorder)
	b.FakeKubeClient().PrependReactor("create", "*", b.generateNameReactor)
	b.FakeCMClient().PrependReactor("create", "*", b.generateNameReactor)
	b.FakeGWClient().PrependReactor("create", "*", b.generateNameReactor)
	b.KubeSharedInformerFactory = kubeinformers.NewSharedInformerFactory(b.Client, informerResyncPeriod)
	b.SharedInformerFactory = informers.NewSharedInformerFactory(b.CMClient, informerResyncPeriod)
	b.GWShared = gwinformers.NewSharedInformerFactory(b.GWClient, informerResyncPeriod)
	b.stopCh = make(chan struct{})
	b.Metrics = metrics.New(logs.Log, clock.RealClock{})

	// set the Clock on the context
	if b.Clock == nil {
		b.Context.Clock = clock.RealClock{}
	} else {
		b.Context.Clock = b.Clock
	}
	// Fix the clock used in apiutil so that calls to set status conditions
	// can be predictably tested
	apiutil.Clock = b.Context.Clock
}

// InitWithRESTConfig() will call builder.Init(), then assign an initialised
// RESTConfig with a `cert-manager/unit-test` User Agent.
func (b *Builder) InitWithRESTConfig() {
	b.Init()
	b.RESTConfig = util.RestConfigWithUserAgent(new(rest.Config), "unit-testing")
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

func (b *Builder) FakeGWClient() *gwfake.Clientset {
	return b.Context.GWClient.(*gwfake.Clientset)
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

// CheckAndFinish will run ensure: all reactors are called, all actions are
// expected, and all events are as expected.
// It will then call the Builder's CheckFn, if defined.
func (b *Builder) CheckAndFinish(args ...interface{}) {
	defer b.Stop()
	if err := b.AllReactorsCalled(); err != nil {
		b.T.Errorf("Not all expected reactors were called: %v", err)
	}
	if err := b.AllActionsExecuted(); err != nil {
		b.T.Errorf(err.Error())
	}
	if err := b.AllEventsCalled(); err != nil {
		b.T.Errorf(err.Error())
	}

	// resync listers before running checks
	b.Sync()
	// run custom checks
	if b.CheckFn != nil {
		b.CheckFn(b, args...)
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

func (b *Builder) AllEventsCalled() error {
	var errs []error
	if !util.EqualUnsorted(b.ExpectedEvents, b.Events()) {
		errs = append(errs, fmt.Errorf("got unexpected events, exp='%s' got='%s'",
			b.ExpectedEvents, b.Events()))
	}

	return utilerrors.NewAggregate(errs)
}

// AllActionsExecuted skips the "list" and "watch" action verbs.
func (b *Builder) AllActionsExecuted() error {
	firedActions := b.FakeCMClient().Actions()
	firedActions = append(firedActions, b.FakeKubeClient().Actions()...)
	firedActions = append(firedActions, b.FakeGWClient().Actions()...)

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
	return fmt.Sprintf("%s %s %q in namespace %s", a.GetVerb(), a.GetSubresource(), a.GetResource(), a.GetNamespace())
}

// Stop will signal the informers to stop watching changes
// This method is *not* safe to be called concurrently
func (b *Builder) Stop() {
	if b.stopCh == nil {
		return
	}

	close(b.stopCh)
	b.stopCh = nil
	// Reset the clock back to the RealClock in apiutil
	apiutil.Clock = clock.RealClock{}
}

func (b *Builder) Start() {
	b.KubeSharedInformerFactory.Start(b.stopCh)
	b.SharedInformerFactory.Start(b.stopCh)
	b.GWShared.Start(b.stopCh)

	// wait for caches to sync
	b.Sync()
}

func (b *Builder) Sync() {
	if err := mustAllSync(b.KubeSharedInformerFactory.WaitForCacheSync(b.stopCh)); err != nil {
		panic("Error waiting for kubeSharedInformerFactory to sync: " + err.Error())
	}
	if err := mustAllSync(b.SharedInformerFactory.WaitForCacheSync(b.stopCh)); err != nil {
		panic("Error waiting for SharedInformerFactory to sync: " + err.Error())
	}
	if err := mustAllSync(b.GWShared.WaitForCacheSync(b.stopCh)); err != nil {
		panic("Error waiting for GWShared to sync: " + err.Error())
	}
	if b.additionalSyncFuncs != nil {
		cache.WaitForCacheSync(b.stopCh, b.additionalSyncFuncs...)
	}
	time.Sleep(informerResyncPeriod)
}

// RegisterAdditionalSyncFuncs registers an additional InformerSynced function
// with the builder.
// When the Sync method is called, the builder will also wait for the given
// listers to be synced as well as the listers that were registered with the
// informer factories that the builder provides.
func (b *Builder) RegisterAdditionalSyncFuncs(fns ...cache.InformerSynced) {
	b.additionalSyncFuncs = append(b.additionalSyncFuncs, fns...)
}

func (b *Builder) Events() []string {
	if e, ok := b.Recorder.(*FakeRecorder); ok {
		return e.Events
	}

	return nil
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
