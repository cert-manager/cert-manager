package issuer

import (
	"sync"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// Constructor constructs an issuer given an Issuer resource and a Context.
// An error will be returned if the appropriate issuer is not registered.
type Constructor func(v1alpha1.GenericIssuer, *Context) (Interface, error)

var (
	constructors     = make(map[string]Constructor)
	constructorsLock sync.RWMutex
)

// Register will register an issuer constructor so it can be used within the
// application. 'name' should be unique, and should be used to identify this
// issuer.
// TODO: move this method to be on Factory, and invent a way to obtain a
// SharedFactory. This will make testing easier.
func Register(name string, c Constructor) {
	constructorsLock.Lock()
	defer constructorsLock.Unlock()
	constructors[name] = c
}
