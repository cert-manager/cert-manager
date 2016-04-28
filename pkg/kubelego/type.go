package kubelego

import (
	"sync"

	"github.com/simonswine/kube-lego/pkg/ingress"

	"github.com/xenolf/lego/acme"
	k8sClient "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/util/intstr"
	"k8s.io/kubernetes/pkg/util/workqueue"
)

type KubeLego struct {
	legoClient       *acme.Client
	legoURL          string
	legoEmail        string
	LegoSecretName   string
	LegoServiceName  string
	LegoIngressName  string
	LegoNamespace    string
	legoHTTPPort     intstr.IntOrString
	legoUser         *LegoUser
	kubeClient       *k8sClient.Client
	legoIngressSlice []*ingress.Ingress
	version          string

	// stop channel for services
	stopCh chan struct{}

	// wait group
	waitGroup sync.WaitGroup

	// work queue
	workQueue *workqueue.Type
}
