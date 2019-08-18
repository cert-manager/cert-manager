package webhook

import (
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/jetstack/cert-manager/pkg/internal/apis/certmanager/install"
)

// Define a Scheme that has all cert-manager API types registered, including
// the internal API version, defaulting functions and conversion functions for
// all external versions.
// This scheme should *only* be used by the webhook as the conversion/defaulter
// functions are likely to change in future, and all controllers consuming
// cert-manager APIs should have a consistent view of all API kinds.

var (
	Scheme = runtime.NewScheme()
)

func init() {
	install.Install(Scheme)
}
