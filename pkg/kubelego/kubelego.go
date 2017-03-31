package kubelego

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jetstack/kube-lego/pkg/acme"
	"github.com/jetstack/kube-lego/pkg/ingress"
	"github.com/jetstack/kube-lego/pkg/kubelego_const"
	"github.com/jetstack/kube-lego/pkg/provider/gce"
	"github.com/jetstack/kube-lego/pkg/provider/nginx"
	"github.com/jetstack/kube-lego/pkg/secret"

	log "github.com/Sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	k8sApi "k8s.io/client-go/pkg/api/v1"
)

var _ kubelego.KubeLego = &KubeLego{}

func makeLog() *log.Entry {
	loglevel := strings.ToLower(os.Getenv("LEGO_LOG_LEVEL"))
	if len(loglevel) == 0 {
		log.SetLevel(log.InfoLevel)
	} else if loglevel == "debug" {
		log.SetLevel(log.DebugLevel)
	} else if loglevel == "info" {
		log.SetLevel(log.InfoLevel)
	} else if loglevel == "warn" {
		log.SetLevel(log.WarnLevel)
	} else if loglevel == "error" {
		log.SetLevel(log.ErrorLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	return log.WithField("context", "kubelego")
}

func New(version string) *KubeLego {
	return &KubeLego{
		version:   version,
		log:       makeLog(),
		stopCh:    make(chan struct{}),
		waitGroup: sync.WaitGroup{},
	}
}

func (kl *KubeLego) Log() *log.Entry {
	return kl.log
}

func (kl *KubeLego) Stop() {
	kl.Log().Info("shutting things down")
	close(kl.stopCh)
}

func (kl *KubeLego) IngressProvider(name string) (provider kubelego.IngressProvider, err error) {
	provider, ok := kl.legoIngressProvider[name]
	if !ok {
		return nil, fmt.Errorf("Ingress provider '%s' not found", name)
	}
	return
}

func (kl *KubeLego) Init() {
	kl.Log().Infof("kube-lego %s starting", kl.version)

	// handle sigterm correctly
	k := make(chan os.Signal, 1)
	signal.Notify(k, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-k
		logger := kl.Log().WithField("signal", s.String())
		logger.Debug("received signal")
		kl.Stop()
	}()

	// parse env vars
	err := kl.paramsLego()
	if err != nil {
		kl.Log().Fatal(err)
	}

	// initialising ingress providers
	kl.legoIngressProvider = map[string]kubelego.IngressProvider{
		"gce":   gce.New(kl),
		"nginx": nginx.New(kl),
	}

	// start workers
	kl.WatchReconfigure()

	// intialize kube api
	err = kl.InitKube()
	if err != nil {
		kl.Log().Fatal(err)
	}

	// run acme http server
	myAcme := acme.New(kl)
	go func() {
		kl.waitGroup.Add(1)
		defer kl.waitGroup.Done()
		myAcme.RunServer(kl.stopCh)
	}()
	kl.acmeClient = myAcme

	// run ticker to check certificates periodically
	ticker := time.NewTicker(kl.legoCheckInterval)
	go func() {
		for timestamp := range ticker.C {
			kl.Log().Infof("Periodically check certificates at %s", timestamp)
			kl.requestReconfigure()
		}
	}()

	// watch for ingress controller events
	kl.WatchEvents()

	// wait for stop signal
	<-kl.stopCh
	ticker.Stop()
	kl.Log().Infof("exiting")
	kl.waitGroup.Wait()
}

func (kl *KubeLego) AcmeClient() kubelego.Acme {
	return kl.acmeClient
}

func (kl *KubeLego) KubeClient() *kubernetes.Clientset {
	return kl.kubeClient
}

func (kl *KubeLego) Version() string {
	return kl.version
}

func (kl *KubeLego) LegoHTTPPort() intstr.IntOrString {
	return kl.legoHTTPPort
}

func (kl *KubeLego) LegoURL() string {
	return kl.legoURL
}

func (kl *KubeLego) LegoEmail() string {
	return kl.legoEmail
}

func (kl *KubeLego) LegoNamespace() string {
	return kl.legoNamespace
}

func (kl *KubeLego) LegoWatchNamespace() string {
	return kl.legoWatchNamespace
}

func (kl *KubeLego) LegoPodIP() net.IP {
	return kl.legoPodIP
}

func (kl *KubeLego) LegoDefaultIngressClass() string {
	return kl.legoDefaultIngressClass
}

func (kl *KubeLego) LegoIngressNameNginx() string {
	return kl.legoIngressNameNginx
}
func (kl *KubeLego) LegoSupportedIngressClass() []string {
	return kl.legoSupportedIngressClass
}

func (kl *KubeLego) LegoServiceNameNginx() string {
	return kl.legoServiceNameNginx
}

func (kl *KubeLego) LegoServiceNameGce() string {
	return kl.legoServiceNameGce
}

func (kl *KubeLego) LegoMinimumValidity() time.Duration {
	return kl.legoMinimumValidity
}

func (kl *KubeLego) LegoCheckInterval() time.Duration {
	return kl.legoCheckInterval
}

func (kl *KubeLego) LegoKubeApiURL() string {
	return kl.legoKubeApiURL
}

func (kl *KubeLego) acmeSecret() *secret.Secret {
	return secret.New(kl, kl.LegoNamespace(), kl.legoSecretName)
}

func (kl *KubeLego) AcmeUser() (map[string][]byte, error) {
	s := kl.acmeSecret()
	if !s.Exists() {
		return map[string][]byte{}, fmt.Errorf("no acme user found %s/%s", kl.LegoNamespace(), kl.legoSecretName)
	}
	return s.SecretApi.Data, nil
}

func (kl *KubeLego) SaveAcmeUser(data map[string][]byte) error {
	s := kl.acmeSecret()
	s.SecretApi.Data = data
	return s.Save()
}

// read config parameters from ENV vars
func (kl *KubeLego) paramsLego() error {

	kl.legoEmail = os.Getenv("LEGO_EMAIL")
	if len(kl.legoEmail) == 0 {
		return errors.New("Please provide an email address for certificate expiration notifications in LEGO_EMAIL (https://letsencrypt.org/docs/expiration-emails/)")
	}

	kl.legoPodIP = net.ParseIP(os.Getenv("LEGO_POD_IP"))
	if kl.legoPodIP == nil {
		return errors.New("Please provide the pod's IP via environment variable LEGO_POD_IP using the downward API (http://kubernetes.io/docs/user-guide/downward-api/)")
	}

	kl.legoNamespace = os.Getenv("LEGO_NAMESPACE")
	if len(kl.legoNamespace) == 0 {
		kl.legoNamespace = k8sApi.NamespaceDefault
	}

	kl.legoURL = os.Getenv("LEGO_URL")
	if len(kl.legoURL) == 0 {
		kl.legoURL = "https://acme-staging.api.letsencrypt.org/directory"
	}

	kl.legoSecretName = os.Getenv("LEGO_SECRET_NAME")
	if len(kl.legoSecretName) == 0 {
		kl.legoSecretName = "kube-lego-account"
	}

	kl.legoServiceNameNginx = os.Getenv("LEGO_SERVICE_NAME_NGINX")
	if len(kl.legoServiceNameNginx) == 0 {
		kl.legoServiceNameNginx = os.Getenv("LEGO_SERVICE_NAME")
		if len(kl.legoServiceNameNginx) == 0 {
			kl.legoServiceNameNginx = "kube-lego-nginx"
		}
	}

	kl.legoServiceNameGce = os.Getenv("LEGO_SERVICE_NAME_GCE")
	if len(kl.legoServiceNameGce) == 0 {
		kl.legoServiceNameGce = "kube-lego-gce"
	}

	kl.legoSupportedIngressClass = strings.Split(os.Getenv("LEGO_SUPPORTED_INGRESS_CLASS"),",")
	if len(kl.legoSupportedIngressClass) == 1 {
		kl.legoSupportedIngressClass = kubelego.SupportedIngressClasses
	}

	legoDefaultIngressClass := os.Getenv("LEGO_DEFAULT_INGRESS_CLASS")
	if len(legoDefaultIngressClass) == 0 {
		kl.legoDefaultIngressClass = "nginx"
	} else {
		var err error = nil
		kl.legoDefaultIngressClass, err = ingress.IsSupportedIngressClass(kl.legoSupportedIngressClass, legoDefaultIngressClass)
		if err != nil {
			return fmt.Errorf("Unsupported default ingress class: '%s'", legoDefaultIngressClass)
		}
	}
	kl.legoIngressNameNginx = os.Getenv("LEGO_INGRESS_NAME_NGINX")
	if len(kl.legoIngressNameNginx) == 0 {
		kl.legoIngressNameNginx = os.Getenv("LEGO_INGRESS_NAME")
		if len(kl.legoIngressNameNginx) == 0 {
			kl.legoIngressNameNginx = "kube-lego-nginx"
		}
	}

	checkIntervalString := os.Getenv("LEGO_CHECK_INTERVAL")
	if len(checkIntervalString) == 0 {
		kl.legoCheckInterval = 8 * time.Hour
	} else {
		d, err := time.ParseDuration(checkIntervalString)
		if err != nil {
			return err
		}
		if d < 5*time.Minute {
			return fmt.Errorf("Minimum check interval is 5 minutes: %s", d)
		}
		kl.legoCheckInterval = d
	}

	kl.legoKubeApiURL = os.Getenv("LEGO_KUBE_API_URL")
	if len(kl.legoKubeApiURL) == 0 {
		kl.legoKubeApiURL = "http://127.0.0.1:8080"
	}

	minimumValidity := os.Getenv("LEGO_MINIMUM_VALIDITY")
	if len(minimumValidity) == 0 {
		kl.legoMinimumValidity = time.Hour * 24 * 30
	} else {
		d, err := time.ParseDuration(minimumValidity)
		if err != nil {
			return err
		}
		if d < 24*time.Hour {
			return fmt.Errorf("Smallest allowed minimum validity is 24 hours: %s", d)
		}
		kl.legoMinimumValidity = d
	}

	httpPortStr := os.Getenv("LEGO_PORT")
	if len(httpPortStr) == 0 {
		kl.legoHTTPPort = intstr.FromInt(8080)
	} else {
		i, err := strconv.Atoi(httpPortStr)
		if err != nil {
			return err
		}
		if i <= 0 || i >= 65535 {
			return fmt.Errorf("Wrong port: %d", i)
		}
		kl.legoHTTPPort = intstr.FromInt(i)
	}

	annotationEnabled := os.Getenv("LEGO_KUBE_ANNOTATION")
	if len(annotationEnabled) != 0 {
		kubelego.AnnotationEnabled = annotationEnabled
	}

	watchNamespace := os.Getenv("LEGO_WATCH_NAMESPACE")
	if len(watchNamespace) == 0 {
		kl.legoWatchNamespace = k8sApi.NamespaceAll
	} else {
		kl.legoWatchNamespace = watchNamespace
	}
	return nil
}
