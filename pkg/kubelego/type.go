package kubelego

import (
	"net"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/workqueue"

	certmanager "github.com/munnerz/cert-manager/pkg/client/clientset_generated/clientset"
	"github.com/munnerz/cert-manager/pkg/ingress"
	"github.com/munnerz/cert-manager/pkg/kubelego_const"
)

type KubeLego struct {
	legoURL                   string
	legoEmail                 string
	legoSecretName            string
	legoIngressNameNginx      string
	legoNamespace             string
	legoPodIP                 net.IP
	legoServiceNameNginx      string
	legoServiceNameGce        string
	legoSupportedIngressClass []string
	legoHTTPPort              intstr.IntOrString
	legoCheckInterval         time.Duration
	legoMinimumValidity       time.Duration
	legoDefaultIngressClass   string
	legoKubeApiURL            string
	legoWatchNamespace        string
	kubeClient                *kubernetes.Clientset
	tprKubeClient             *certmanager.Clientset
	legoIngressSlice          []*ingress.Ingress
	legoIngressProvider       map[string]kubelego.IngressProvider
	log                       *log.Entry
	version                   string
	acmeClient                kubelego.Acme

	// stop channel for services
	stopCh chan struct{}

	// wait group
	waitGroup sync.WaitGroup

	// work queue
	workQueue *workqueue.Type
}
