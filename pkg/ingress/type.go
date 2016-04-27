package ingress

import (
	"github.com/simonswine/kube-lego/pkg/kubelego_const"

	k8sExtensions "k8s.io/kubernetes/pkg/apis/extensions"
)

type Ingress struct {
	IngressApi *k8sExtensions.Ingress
	exists    bool
	kubelego  kubelego.KubeLego
}
