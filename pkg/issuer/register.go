package issuer

import (
	"sync"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
)

type Constructor func(*v1alpha1.Issuer, *Context) (Interface, error)

var (
	constructors     = make(map[string]Constructor)
	constructorsLock sync.RWMutex
)
