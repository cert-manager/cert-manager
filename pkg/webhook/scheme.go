package webhook

import (
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/internal/apis/certmanager/install"
)

var (
	Scheme = runtime.NewScheme()
)

func init() {
	v1alpha1.AddToScheme(Scheme)
	install.Install(Scheme)
}
