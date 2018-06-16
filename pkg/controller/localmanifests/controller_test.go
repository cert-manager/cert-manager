package localmanifests

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	cltesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/client/clientset/versioned/fake"
	informers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
)

const (
	noResync = time.Duration(0)
)

type fixture struct {
	cl *fake.Clientset
	// if cl is nil, a new client will be created with these objects
	clientObjects []runtime.Object
	// reactors is an optional set of custom client reactors
	reactors []reactor

	// optional manifests path. If not set, a temporary directory will be
	// created and used.
	manifestsPath        string
	cleanupManifestsPath bool

	// optional custom workqueue. If not set, a default rate limiting workqueue
	// will be used
	workqueue workqueue.RateLimitingInterface

	// optional custom SharedInformerFactory. If not set, an informer based on
	// the fake client will be used.
	factory informers.SharedInformerFactory
	stopCh  chan struct{}

	// this will be set after a call to controller()
	c *Controller
}

func (f *fixture) controller() *Controller {
	if f.c != nil {
		return f.c
	}

	f.c = &Controller{
		cmClient:              f.cl,
		issuerInformer:        f.factory.Certmanager().V1alpha1().Issuers(),
		clusterIssuerInformer: f.factory.Certmanager().V1alpha1().ClusterIssuers(),
		certificateInformer:   f.factory.Certmanager().V1alpha1().Certificates(),
		manifestsPath:         f.manifestsPath,
		queue:                 f.workqueue,
	}
	// we call these informers so that WaitForCacheSync will ensure the listers
	// are synced.
	f.c.issuerInformer.Informer()
	f.c.clusterIssuerInformer.Informer()
	f.c.certificateInformer.Informer()

	f.factory.Start(f.stopCh)
	f.factory.WaitForCacheSync(f.stopCh)
	return f.c
}

func (f *fixture) init(t *testing.T) {
	if f.cl == nil {
		f.cl = fake.NewSimpleClientset(f.clientObjects...)
	}
	for _, r := range f.reactors {
		f.cl.PrependReactor(r.verb, r.resource, r.fn)
	}
	if f.workqueue == nil {
		f.workqueue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*2, time.Minute*1), "localmanifests")
	}
	if f.factory == nil {
		f.factory = informers.NewSharedInformerFactory(f.cl, noResync)
	}
	if f.manifestsPath == "" {
		var err error
		f.manifestsPath, err = ioutil.TempDir("", "cert-manager-unit")
		if err != nil {
			t.Errorf("error creating temporary manifest directory: %v", err)
			t.FailNow()
			return
		}
		f.cleanupManifestsPath = true
	}
	f.stopCh = make(chan struct{})
}

func (f *fixture) cleanup(t *testing.T) {
	if f.cleanupManifestsPath {
		err := os.RemoveAll(f.manifestsPath)
		if err != nil {
			t.Errorf("error cleaning up temporary manifests directory: %v", err)
		}
	}
	close(f.stopCh)
}

func (f *fixture) filterActions(actions []cltesting.Action) []cltesting.Action {
	var out []cltesting.Action
	for _, a := range actions {
		switch a.GetVerb() {
		case "list", "watch":
			continue
		default:
			out = append(out, a)
		}
	}
	return out
}

// This is a special test to ensure the 'e2e' functionality of this controller.
// It will perform a test where 'create' requests to the API server are failing,
// and ensure that:
//
// 1) the object is instead directly added to a lister
// 2) an informer that is watching for resources of that type has its OnAdd fn fired
//
// This is effectively a verification that this control loop does what is was
// originally designed to do.
func TestRunControllerTriggersInformers(t *testing.T) {
	clusterIssuerGVK := v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.ClusterIssuerKind)
	basicClusterIssuer := &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
	}

	// create/init fixture
	f := &fixture{
		reactors: []reactor{
			{"create", "clusterissuers",
				func(action cltesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("unknown failure")
				}},
		},
	}
	f.init(t)
	defer f.cleanup(t)

	addFnCalledCh := make(chan struct{})
	defer close(addFnCalledCh)
	// use the informer to add an AddFunc which verifies that the informer calls
	// its handlers when we manually add items to a lister
	f.factory.Certmanager().V1alpha1().ClusterIssuers().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			// signal that the AddFunc has been called
			close(addFnCalledCh)
		},
	})

	c := f.controller()
	// run test
	err := c.runController(&clusterIssuerGVK, basicClusterIssuer)
	// check basic err status
	if err == nil {
		t.Errorf("expected an error, but got none")
	}

	// ++++++++++++
	// this block of checks is copied from the 'TestRunController' test below
	// ++++++++++++

	// first we verify that the 'create' endpoint was called.
	// this request will have failed, but we check it anyway to ensure
	// behaviour stays consistent
	actions := f.filterActions(f.cl.Actions())
	if len(actions) != 1 {
		t.Errorf("expected 1 action but got: %v", actions)
		return
	}
	a := actions[0]
	if !a.Matches("create", "clusterissuers") {
		t.Errorf("expected 'create clusterissuers' action but got: %v", a)
		return
	}
	createAction := a.(cltesting.CreateAction)
	obj := createAction.GetObject().(*v1alpha1.ClusterIssuer)
	if !reflect.DeepEqual(basicClusterIssuer, obj) {
		t.Errorf("expected %v to equal %v", obj, basicClusterIssuer)
		return
	}

	// then check to make sure the clientset does not have a copy of
	// the expected resource (as the create should have failed)
	_, err = f.cl.CertmanagerV1alpha1().ClusterIssuers().Get(obj.Name, metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected not found error, but got: %v", err)
		return
	}

	// now ensure that the Lister *does* contain a copy of the resource
	listerObj, err := f.controller().clusterIssuerInformer.Lister().Get(obj.Name)
	if err != nil {
		t.Errorf("expected no error, but got: %v", err)
		return
	}
	if !reflect.DeepEqual(basicClusterIssuer, listerObj) {
		t.Errorf("expected %v to equal %v", listerObj, basicClusterIssuer)
		return
	}

	// verify that the AddFunc has been called as a result of the item being added
	// to the lister
	waitDuration := time.Second * 2
	waitForAddFunc, cancel := context.WithTimeout(context.Background(), waitDuration)
	defer cancel()
	select {
	case <-addFnCalledCh:
		break
	case <-waitForAddFunc.Done():
		t.Errorf("expected informer AddFunc to be called, but it was not after %v", waitDuration)
	}
}

func TestRunController(t *testing.T) {
	certGVK := v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.CertificateKind)
	basicCertificate := &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "abc",
		},
	}

	issuerGVK := v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.IssuerKind)
	basicIssuer := &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "abc",
		},
	}

	clusterIssuerGVK := v1alpha1.SchemeGroupVersion.WithKind(v1alpha1.ClusterIssuerKind)
	basicClusterIssuer := &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
	}

	type testT struct {
		// test function args
		gvk schema.GroupVersionKind
		obj runtime.Object
		// whether to expect an error
		expectedErr bool
		// set of objects to load into the fake clientset
		clientObjects []runtime.Object
		// function to verify the state of the fixture after test
		verify func(t *testing.T, test testT, f *fixture)
		// custom clientset reaction funcs
		reactors []reactor
	}

	tests := map[string]testT{
		"should create certificate without touching lister if possible": {
			gvk:         certGVK,
			obj:         basicCertificate.DeepCopy(),
			expectedErr: false,
			verify: func(t *testing.T, test testT, f *fixture) {
				actions := f.filterActions(f.cl.Actions())
				if len(actions) != 1 {
					t.Errorf("expected 1 action but got: %v", actions)
					return
				}
				a := actions[0]
				if !a.Matches("create", "certificates") {
					t.Errorf("expected 'create certificates' action but got: %v", a)
					return
				}
				createAction := a.(cltesting.CreateAction)
				obj := createAction.GetObject().(*v1alpha1.Certificate)
				if !reflect.DeepEqual(test.obj, obj) {
					t.Errorf("expected %v to equal %v", obj, test.obj)
					return
				}
			},
		},
		"should create issuer without touching lister if possible": {
			gvk:         issuerGVK,
			obj:         basicIssuer.DeepCopy(),
			expectedErr: false,
			verify: func(t *testing.T, test testT, f *fixture) {
				actions := f.filterActions(f.cl.Actions())
				if len(actions) != 1 {
					t.Errorf("expected 1 action but got: %v", actions)
					return
				}
				a := actions[0]
				if !a.Matches("create", "issuers") {
					t.Errorf("expected 'create issuers' action but got: %v", a)
					return
				}
				createAction := a.(cltesting.CreateAction)
				obj := createAction.GetObject().(*v1alpha1.Issuer)
				if !reflect.DeepEqual(test.obj, obj) {
					t.Errorf("expected %v to equal %v", obj, test.obj)
					return
				}
			},
		},
		"should create clusterissuer without touching lister if possible": {
			gvk:         clusterIssuerGVK,
			obj:         basicClusterIssuer.DeepCopy(),
			expectedErr: false,
			verify: func(t *testing.T, test testT, f *fixture) {
				actions := f.filterActions(f.cl.Actions())
				if len(actions) != 1 {
					t.Errorf("expected 1 action but got: %v", actions)
					return
				}
				a := actions[0]
				if !a.Matches("create", "clusterissuers") {
					t.Errorf("expected 'create clusterissuers' action but got: %v", a)
					return
				}
				createAction := a.(cltesting.CreateAction)
				obj := createAction.GetObject().(*v1alpha1.ClusterIssuer)
				if !reflect.DeepEqual(test.obj, obj) {
					t.Errorf("expected %v to equal %v", obj, test.obj)
					return
				}
			},
		},
		"should manually add resource to indexer if persisting fails & return an error": {
			gvk:         clusterIssuerGVK,
			obj:         basicClusterIssuer.DeepCopy(),
			expectedErr: true,
			verify: func(t *testing.T, test testT, f *fixture) {
				// first we verify that the 'create' endpoint was called.
				// this request will have failed, but we check it anyway to ensure
				// behaviour stays consistent
				actions := f.filterActions(f.cl.Actions())
				if len(actions) != 1 {
					t.Errorf("expected 1 action but got: %v", actions)
					return
				}
				a := actions[0]
				if !a.Matches("create", "clusterissuers") {
					t.Errorf("expected 'create clusterissuers' action but got: %v", a)
					return
				}
				createAction := a.(cltesting.CreateAction)
				obj := createAction.GetObject().(*v1alpha1.ClusterIssuer)
				if !reflect.DeepEqual(test.obj, obj) {
					t.Errorf("expected %v to equal %v", obj, test.obj)
					return
				}

				// then check to make sure the clientset does not have a copy of
				// the expected resource (as the create should have failed)
				_, err := f.cl.CertmanagerV1alpha1().ClusterIssuers().Get(obj.Name, metav1.GetOptions{})
				if !apierrors.IsNotFound(err) {
					t.Errorf("expected not found error, but got: %v", err)
					return
				}

				// now ensure that the Lister *does* contain a copy of the resource
				listerObj, err := f.controller().clusterIssuerInformer.Lister().Get(obj.Name)
				if err != nil {
					t.Errorf("expected no error, but got: %v", err)
					return
				}
				if !reflect.DeepEqual(test.obj, listerObj) {
					t.Errorf("expected %v to equal %v", listerObj, test.obj)
					return
				}
			},
			reactors: []reactor{
				{"create", "clusterissuers",
					func(action cltesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("unknown failure")
					}},
			},
		},
	}

	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			// create/init fixture
			f := &fixture{
				clientObjects: test.clientObjects,
				reactors:      test.reactors,
			}
			f.init(t)
			defer f.cleanup(t)
			c := f.controller()
			// run test
			err := c.runController(&test.gvk, test.obj)
			// check basic err status
			if err != nil && !test.expectedErr {
				t.Errorf("expected no error, but got: %v", err)
			} else if err == nil && test.expectedErr {
				t.Errorf("expected an error, but got none")
			}

			// verify expected actions/state
			if test.verify != nil {
				test.verify(t, test, f)
			}
		})
	}
}

func TestPersistCertificate(t *testing.T) {
	basicCertificate := &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "abc",
		},
	}
	basicCertificateWithRV := basicCertificate.DeepCopy()
	basicCertificateWithRV.ResourceVersion = "10"

	type testT struct {
		toPersist     runtime.Object
		clientObjects []runtime.Object
		expectedErr   bool
		verify        func(t *testing.T, test testT, f *fixture)
		reactors      []reactor
	}
	tests := map[string]testT{
		"should create a Certificate if it does not exist": {
			// define test vars
			toPersist:     basicCertificate.DeepCopy(),
			clientObjects: []runtime.Object{},
			expectedErr:   false,
			verify: func(t *testing.T, test testT, f *fixture) {
				actions := f.filterActions(f.cl.Actions())
				if len(actions) != 1 {
					t.Errorf("expected 1 action but got: %v", actions)
					return
				}
				a := actions[0]
				if !a.Matches("create", "certificates") {
					t.Errorf("expected 'create certificates' action but got: %v", a)
					return
				}
				createAction := a.(cltesting.CreateAction)
				obj := createAction.GetObject().(*v1alpha1.Certificate)
				if !reflect.DeepEqual(test.toPersist, obj) {
					t.Errorf("expected %v to equal %v", obj, test.toPersist)
					return
				}
			},
		},
		"should update a Certificate if one already exists": {
			// define test vars
			toPersist:     basicCertificate.DeepCopy(),
			clientObjects: []runtime.Object{basicCertificateWithRV.DeepCopy()},
			expectedErr:   false,
			verify: func(t *testing.T, test testT, f *fixture) {
				actions := f.filterActions(f.cl.Actions())
				if len(actions) != 1 {
					t.Errorf("expected 1 action but got: %v", actions)
					return
				}
				a := actions[0]
				if !a.Matches("update", "certificates") {
					t.Errorf("expected 'update certificates' action but got: %v", a)
					return
				}
				updateAction := a.(cltesting.UpdateAction)
				obj := updateAction.GetObject().(*v1alpha1.Certificate)
				metaToPersist := test.toPersist.(metav1.Object)
				metaToPersist.SetResourceVersion(obj.ResourceVersion)
				if !reflect.DeepEqual(test.toPersist, obj) {
					t.Errorf("expected %v to equal %v", obj, test.toPersist)
					return
				}
			},
		},
		"should error on failure to create": {
			// define test vars
			toPersist:     basicCertificate.DeepCopy(),
			clientObjects: []runtime.Object{},
			expectedErr:   true,
			reactors: []reactor{
				{"create", "certificates",
					func(action cltesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("unknown failure")
					}},
			},
		},
		"should error on failure to update": {
			// define test vars
			toPersist:     basicCertificate.DeepCopy(),
			clientObjects: []runtime.Object{basicCertificateWithRV},
			expectedErr:   true,
			reactors: []reactor{
				{"update", "certificates",
					func(action cltesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("unknown failure")
					}},
			},
		},
		"should error with invalid resource": {
			toPersist:   &v1alpha1.Issuer{},
			expectedErr: true,
		},
	}

	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			// create/init fixture
			f := &fixture{
				clientObjects: test.clientObjects,
				reactors:      test.reactors,
			}
			f.init(t)
			defer f.cleanup(t)
			c := f.controller()
			// run test
			err := c.persistCertificate(test.toPersist)
			// check basic err status
			if err != nil && !test.expectedErr {
				t.Errorf("expected no error, but got: %v", err)
			} else if err == nil && test.expectedErr {
				t.Errorf("expected an error, but got none")
			}

			// verify expected actions/state
			if test.verify != nil {
				test.verify(t, test, f)
			}
		})
	}
}

func TestPersistIssuer(t *testing.T) {
	basicIssuer := &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "abc",
		},
	}
	basicIssuerWithRV := &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test",
			Namespace:       "abc",
			ResourceVersion: "10",
		},
	}
	type testT struct {
		toPersist     runtime.Object
		clientObjects []runtime.Object
		expectedErr   bool
		verify        func(t *testing.T, test testT, f *fixture)
		reactors      []reactor
	}
	tests := map[string]testT{
		"should create a Issuer if it does not exist": {
			// define test vars
			toPersist:     basicIssuer.DeepCopy(),
			clientObjects: []runtime.Object{},
			expectedErr:   false,
			verify: func(t *testing.T, test testT, f *fixture) {
				actions := f.filterActions(f.cl.Actions())
				if len(actions) != 1 {
					t.Errorf("expected 1 action but got: %v", actions)
					return
				}
				a := actions[0]
				if !a.Matches("create", "issuers") {
					t.Errorf("expected 'create issuers' action but got: %v", a)
					return
				}
				createAction := a.(cltesting.CreateAction)
				obj := createAction.GetObject().(*v1alpha1.Issuer)
				if !reflect.DeepEqual(test.toPersist, obj) {
					t.Errorf("expected %v to equal %v", obj, test.toPersist)
					return
				}
			},
		},
		"should update a Issuer if one already exists": {
			// define test vars
			toPersist:     basicIssuer.DeepCopy(),
			clientObjects: []runtime.Object{basicIssuerWithRV.DeepCopy()},
			expectedErr:   false,
			verify: func(t *testing.T, test testT, f *fixture) {
				actions := f.filterActions(f.cl.Actions())
				if len(actions) != 1 {
					t.Errorf("expected 1 action but got: %v", actions)
					return
				}
				a := actions[0]
				if !a.Matches("update", "issuers") {
					t.Errorf("expected 'update issuers' action but got: %v", a)
					return
				}
				updateAction := a.(cltesting.UpdateAction)
				obj := updateAction.GetObject().(*v1alpha1.Issuer)
				metaToPersist := test.toPersist.(metav1.Object)
				metaToPersist.SetResourceVersion(obj.ResourceVersion)
				if !reflect.DeepEqual(test.toPersist, obj) {
					t.Errorf("expected %v to equal %v", obj, test.toPersist)
					return
				}
			},
		},
		"should error on failure to create": {
			// define test vars
			toPersist:     basicIssuer.DeepCopy(),
			clientObjects: []runtime.Object{},
			expectedErr:   true,
			reactors: []reactor{
				{"create", "issuers",
					func(action cltesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("unknown failure")
					}},
			},
		},
		"should error on failure to update": {
			// define test vars
			toPersist:     basicIssuer.DeepCopy(),
			clientObjects: []runtime.Object{basicIssuerWithRV},
			expectedErr:   true,
			reactors: []reactor{
				{"update", "issuers",
					func(action cltesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("unknown failure")
					}},
			},
		},
		"should error with invalid resource": {
			toPersist:   &v1alpha1.Certificate{},
			expectedErr: true,
		},
	}

	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			// create/init fixture
			f := &fixture{
				clientObjects: test.clientObjects,
				reactors:      test.reactors,
			}
			f.init(t)
			defer f.cleanup(t)
			c := f.controller()
			// run test
			err := c.persistIssuer(test.toPersist)
			// check basic err status
			if err != nil && !test.expectedErr {
				t.Errorf("expected no error, but got: %v", err)
			} else if err == nil && test.expectedErr {
				t.Errorf("expected an error, but got none")
			}

			// verify expected actions/state
			if test.verify != nil {
				test.verify(t, test, f)
			}
		})
	}
}

func TestPersistClusterIssuer(t *testing.T) {
	basicClusterIssuer := &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
	}
	basicClusterIssuerWithRV := &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test",
			ResourceVersion: "10",
		},
	}
	type testT struct {
		toPersist     runtime.Object
		clientObjects []runtime.Object
		expectedErr   bool
		verify        func(t *testing.T, test testT, f *fixture)
		reactors      []reactor
	}
	tests := map[string]testT{
		"should create a ClusterIssuer if it does not exist": {
			// define test vars
			toPersist:     basicClusterIssuer.DeepCopy(),
			clientObjects: []runtime.Object{},
			expectedErr:   false,
			verify: func(t *testing.T, test testT, f *fixture) {
				actions := f.filterActions(f.cl.Actions())
				if len(actions) != 1 {
					t.Errorf("expected 1 action but got: %v", actions)
					return
				}
				a := actions[0]
				if !a.Matches("create", "clusterissuers") {
					t.Errorf("expected 'create clusterissuers' action but got: %v", a)
					return
				}
				createAction := a.(cltesting.CreateAction)
				obj := createAction.GetObject().(*v1alpha1.ClusterIssuer)
				if !reflect.DeepEqual(test.toPersist, obj) {
					t.Errorf("expected %v to equal %v", obj, test.toPersist)
					return
				}
			},
		},
		"should update a ClusterIssuer if one already exists": {
			// define test vars
			toPersist:     basicClusterIssuer.DeepCopy(),
			clientObjects: []runtime.Object{basicClusterIssuerWithRV.DeepCopy()},
			expectedErr:   false,
			verify: func(t *testing.T, test testT, f *fixture) {
				actions := f.filterActions(f.cl.Actions())
				if len(actions) != 1 {
					t.Errorf("expected 1 action but got: %v", actions)
					return
				}
				a := actions[0]
				if !a.Matches("update", "clusterissuers") {
					t.Errorf("expected 'update clusterissuers' action but got: %v", a)
					return
				}
				updateAction := a.(cltesting.UpdateAction)
				obj := updateAction.GetObject().(*v1alpha1.ClusterIssuer)
				metaToPersist := test.toPersist.(metav1.Object)
				metaToPersist.SetResourceVersion(obj.ResourceVersion)
				if !reflect.DeepEqual(test.toPersist, obj) {
					t.Errorf("expected %v to equal %v", obj, test.toPersist)
					return
				}
			},
		},
		"should error on failure to create": {
			// define test vars
			toPersist:     basicClusterIssuer.DeepCopy(),
			clientObjects: []runtime.Object{},
			expectedErr:   true,
			reactors: []reactor{
				{"create", "clusterissuers",
					func(action cltesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("unknown failure")
					}},
			},
		},
		"should error on failure to update": {
			// define test vars
			toPersist:     basicClusterIssuer.DeepCopy(),
			clientObjects: []runtime.Object{basicClusterIssuerWithRV},
			expectedErr:   true,
			reactors: []reactor{
				{"update", "clusterissuers",
					func(action cltesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("unknown failure")
					}},
			},
		},
		"should error with invalid resource": {
			toPersist:   &v1alpha1.Certificate{},
			expectedErr: true,
		},
	}

	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			// create/init fixture
			f := &fixture{
				clientObjects: test.clientObjects,
				reactors:      test.reactors,
			}
			f.init(t)
			defer f.cleanup(t)
			c := f.controller()
			// run test
			err := c.persistClusterIssuer(test.toPersist)
			// check basic err status
			if err != nil && !test.expectedErr {
				t.Errorf("expected no error, but got: %v", err)
			} else if err == nil && test.expectedErr {
				t.Errorf("expected an error, but got none")
			}

			// verify expected actions/state
			if test.verify != nil {
				test.verify(t, test, f)
			}
		})
	}
}

// todo: probably move this structure out of this package into some kind of testutils
type reactor struct {
	verb, resource string
	fn             cltesting.ReactionFunc
}
