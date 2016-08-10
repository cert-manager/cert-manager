package kubelego

import (
	"sync"
	"time"

	"github.com/jetstack/kube-lego/pkg/ingress"
	"github.com/jetstack/kube-lego/pkg/kubelego_const"

	k8sClient "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/util/intstr"
	"k8s.io/kubernetes/pkg/util/workqueue"
	"net"
)

type KubeLego struct {
	legoURL                 string
	legoEmail               string
	legoSecretName          string
	legoIngressNameNginx    string
	legoNamespace           string
	legoPodIP               net.IP
	legoServiceNameNginx    string
	legoServiceNameGce      string
	legoHTTPPort            intstr.IntOrString
	legoCheckInterval       time.Duration
	legoMinimumValidity     time.Duration
	legoDefaultIngressClass string
	kubeClient              *k8sClient.Client
	legoIngressSlice        []*ingress.Ingress
	legoIngressProvider     map[string]kubelego.IngressProvider
	version                 string
	acmeClient              kubelego.Acme

	// stop channel for services
	stopCh chan struct{}

	// wait group
	waitGroup sync.WaitGroup

	// work queue
	workQueue *workqueue.Type
}
