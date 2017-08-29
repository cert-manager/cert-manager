package controller

import (
	"fmt"
	"sync"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	"github.com/jetstack-experimental/cert-manager/pkg/client"
	cminformers "github.com/jetstack-experimental/cert-manager/pkg/informers"
)

var defaultFactory = &Factory{
	constructors: make(map[string]Constructor),
	controllers:  make(map[string]Controller),
}

func SharedFactory() *Factory {
	return defaultFactory
}

type Factory struct {
	constructors     map[string]Constructor
	constructorsLock sync.RWMutex

	controllers     map[string]Controller
	controllersLock sync.RWMutex

	client    kubernetes.Interface
	cmClient  client.Interface
	factory   informers.SharedInformerFactory
	cmFactory cminformers.SharedInformerFactory
}

func (f *Factory) Setup(client kubernetes.Interface,
	cmClient client.Interface,
	factory informers.SharedInformerFactory,
	cmFactory cminformers.SharedInformerFactory) {
	f.client = client
	f.cmClient = cmClient
	f.factory = factory
	f.cmFactory = cmFactory
}

// Register will register a controller constructor so it can be used within the
// application. 'name' should be unique, and should be used to identify this
// control loop.
func (f *Factory) Register(name string, c Constructor) {
	f.constructorsLock.Lock()
	defer f.constructorsLock.Unlock()
	f.constructors[name] = c
}

// Controller returns a controller with the given name, or an error if it is
// not registered.
func (f *Factory) Controller(name string) (Controller, error) {
	if ctrl := f.getController(name); ctrl != nil {
		return ctrl, nil
	}
	return f.initController(name)
}

// getController will return the controller with the given name, or nil if it
// has not yet been initialised
func (f *Factory) getController(name string) Controller {
	f.controllersLock.RLock()
	defer f.controllersLock.RUnlock()
	if ctrl, ok := f.controllers[name]; ok {
		return ctrl
	}
	return nil
}

// initController initialises a controller with the given name by calling its
// registered constructor function. It will overwrite any references to
// an existing controller with the same name in the shared controller map
func (f *Factory) initController(name string) (Controller, error) {
	f.constructorsLock.RLock()
	defer f.constructorsLock.RUnlock()
	if constructor, ok := f.constructors[name]; ok {
		f.controllersLock.Lock()
		defer f.controllersLock.Unlock()
		ctrl, err := constructor(f.client, f.cmClient, f.factory, f.cmFactory)
		if err != nil {
			return nil, fmt.Errorf("error instantiating controller '%s': %s", name, err.Error())
		}
		f.controllers[name] = ctrl
		return ctrl, nil
	}
	return nil, fmt.Errorf("controller '%s' not registered", name)
}

// Constructor is a function that constructs a cert-manager Controller. This
// will set up informer event handlers.
type Constructor func(client kubernetes.Interface,
	cmClient client.Interface,
	factory informers.SharedInformerFactory,
	cmFactory cminformers.SharedInformerFactory) (Controller, error)

// Controller is a control loop to be run within cert-manager. It should watch
// and act on a single resource type in an API server.
type Controller interface {
	// Run should start this controller with the given number of workers.
	// stopCh should be used to stop the worker running.
	Run(workers int, stopCh <-chan struct{})
}
