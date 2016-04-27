package kubelego

import (
	"github.com/simonswine/kube-lego/pkg/ingress"

	"github.com/xenolf/lego/acme"
	k8sClient "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/util/intstr"
)

type KubeLego struct {
	legoClient       *acme.Client
	LegoURL          string
	LegoEmail        string
	LegoSecretName   string
	LegoServiceName  string
	LegoIngressName  string
	LegoNamespace    string
	LegoHTTPPort     intstr.IntOrString
	legoUser         *LegoUser
	kubeClient       *k8sClient.Client
	legoIngressSlice []*ingress.Ingress
	version string
}
