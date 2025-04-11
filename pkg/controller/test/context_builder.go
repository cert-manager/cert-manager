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
	"slices"
	"testing"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/rand"
	kubefake "k8s.io/client-go/kubernetes/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/client-go/rest"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/utils/clock"
	fakeclock "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	gwfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
	gwinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmfake "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	informers "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/logs"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	"github.com/cert-manager/cert-manager/pkg/util"
	discoveryfake "github.com/cert-manager/cert-manager/test/unit/discovery"
)

func init() {
	logs.InitLogs()
	_ = flag.Set("alsologtostderr", "true")
	_ = flag.Set("v", "4")
	ctrl.SetLogger(logf.Log)
}

type StringGenerator func(n int) string

// Builder is a structure used to construct new Contexts for use during tests.
// Currently, only KubeObjects, CertManagerObjects and GWObjects can be
// specified. These will be auto loaded into the constructed fake Clientsets.
// Call ToContext() to construct a new context using the given values.
type Builder struct {
	T *testing.T

	KubeObjects            []runtime.Object
	CertManagerObjects     []runtime.Object
	GWObjects              []runtime.Object
	PartialMetadataObjects []runtime.Object
	ExpectedActions        []Action
	ExpectedEvents         []string
	StringGenerator        StringGenerator

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

	stopCh chan struct{}

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

// informerResyncPeriod is the resync period used by the test informers. We
// want this period to be as short as possible to make the tests faster.
// However, client-go imposes a minimum resync period of 1 second, so that
// is the lowest we can go.
// https://github.com/kubernetes/client-go/blob/5a019202120ab4dd7dfb3788e5cb87269f343ebe/tools/cache/shared_informer.go#L575
const informerResyncPeriod = time.Second

// Init will construct a new context for this builder and set default values
// for any unset fields.
func (b *Builder) Init() {
	if b.Context == nil {
		b.Context = &controller.Context{}
	}
	if b.Context.RootContext == nil {
		b.Context.RootContext = context.Background()
	}
	if b.StringGenerator == nil {
		b.StringGenerator = rand.String
	}
	scheme := metadatafake.NewTestScheme()
	if err := metav1.AddMetaToScheme(scheme); err != nil {
		b.T.Fatalf("error adding meta to scheme: %v", err)
	}
	b.ACMEOptions.ACMEHTTP01SolverRunAsNonRoot = true // default from cmd/controller/app/options/options.go
	b.Client = kubefake.NewSimpleClientset(b.KubeObjects...)
	b.CMClient = cmfake.NewSimpleClientset(b.CertManagerObjects...)
	b.GWClient = gwfake.NewSimpleClientset(b.GWObjects...)
	b.MetadataClient = metadatafake.NewSimpleMetadataClient(scheme, b.PartialMetadataObjects...)
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
	b.FakeMetadataClient().PrependReactor("create", "*", b.generateNameReactor)
	b.KubeSharedInformerFactory = internalinformers.NewBaseKubeInformerFactory(b.Client, informerResyncPeriod, "")
	b.SharedInformerFactory = informers.NewSharedInformerFactory(b.CMClient, informerResyncPeriod)
	b.GWShared = gwinformers.NewSharedInformerFactory(b.GWClient, informerResyncPeriod)
	b.HTTP01ResourceMetadataInformersFactory = metadatainformer.NewFilteredSharedInformerFactory(b.MetadataClient, informerResyncPeriod, "", func(listOptions *metav1.ListOptions) {})
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

func (b *Builder) FakeKubeInformerFactory() internalinformers.KubeInformerFactory {
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

func (b *Builder) FakeMetadataClient() *metadatafake.FakeMetadataClient {
	return b.Context.MetadataClient.(*metadatafake.FakeMetadataClient)
}

func (b *Builder) FakeDiscoveryClient() *discoveryfake.Discovery {
	return b.Context.DiscoveryClient.(*discoveryfake.Discovery)
}

// CheckAndFinish will run ensure: all reactors are called, all actions are
// expected, and all events are as expected.
// It will then call the Builder's CheckFn, if defined.
func (b *Builder) CheckAndFinish(args ...interface{}) {
	defer b.Stop()
	if err := b.AllActionsExecuted(); err != nil {
		b.T.Error(err)
	}
	if err := b.AllEventsCalled(); err != nil {
		b.T.Error(err)
	}

	// resync listers before running checks
	b.Sync()
	// run custom checks
	if b.CheckFn != nil {
		b.CheckFn(b, args...)
	}
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
	missingActions := slices.Clone(b.ExpectedActions)
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
	b.HTTP01ResourceMetadataInformersFactory.Start(b.stopCh)

	// wait for caches to sync
	b.Sync()
}

// Sync is a function used by tests to wait for all informers to be synced. This function
// is called initially by the Start method, to wait for the caches to be populated. It is
// also called directly by tests to wait for any updates made by the fake clients to be
// reflected in the informer caches.
// Sync calls the WaitForCacheSync method on all informers to make sure they have populated
// their caches. The WaitForCacheSync method is only useful at startup. In order to wait
// for updates made by the fake clients to be reflected in the informer caches, we need
// to sleep for the informerResyncPeriod.
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
	if err := mustAllSync(b.HTTP01ResourceMetadataInformersFactory.WaitForCacheSync(b.stopCh)); err != nil {
		panic("Error waiting for MetadataInformerFactory to sync:" + err.Error())
	}

	// Wait for the informerResyncPeriod to make sure any update made by any of the fake clients
	// is reflected in the informer caches.
	time.Sleep(informerResyncPeriod)
}

func (b *Builder) Events() []string {
	if e, ok := b.Recorder.(*FakeRecorder); ok {
		return e.Events
	}

	return nil
}

func mustAllSync[E comparable](in map[E]bool) error {
	var errs []error
	for t, started := range in {
		if !started {
			errs = append(errs, fmt.Errorf("informer for %v not synced", t))
		}
	}
	return utilerrors.NewAggregate(errs)
}
