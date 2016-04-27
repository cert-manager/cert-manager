package kubelego

import (
	"os"
	"errors"
	"fmt"
	"strconv"

	"k8s.io/kubernetes/pkg/util/intstr"
	log "github.com/Sirupsen/logrus"
	k8sApi "k8s.io/kubernetes/pkg/api"
	k8sClient "k8s.io/kubernetes/pkg/client/unversioned"
	"github.com/xenolf/lego/acme"
)

func New(version string) *KubeLego {
	return &KubeLego{
		version: version,
	}
}

func (kl *KubeLego) Log() *log.Entry {
	log.SetLevel(log.DebugLevel)
	return log.WithField("context", "kubelego")
}

func (kl *KubeLego) Init() {
	kl.Log().Infof("kube-lego %s starting", kl.version)

	// parse env vars
	err := kl.paramsLego()
	if err != nil {
		kl.Log().Fatal(err)
	}

	err = kl.InitKube()
	if err != nil {
		kl.Log().Fatal(err)
	}

	err = kl.InitLego()
	if err != nil {
		kl.Log().Fatal(err)
	}

	kl.WatchConfig()
}

func (kl *KubeLego) KubeClient() *k8sClient.Client {
	return kl.kubeClient
}

func (kl *KubeLego) LegoClient() *acme.Client  {
	return kl.legoClient
}

// read config parameters from ENV vars
func (kl *KubeLego) paramsLego() error {

	kl.LegoEmail = os.Getenv("LEGO_EMAIL")
	if len(kl.LegoEmail) == 0 {
		return errors.New("Please provide an email address for cert recovery in LEGO_EMAIL")
	}

	kl.LegoNamespace = os.Getenv("LEGO_NAMESPACE")
	if len(kl.LegoNamespace) == 0 {
		kl.LegoNamespace = k8sApi.NamespaceDefault
	}

	kl.LegoURL = os.Getenv("LEGO_URL")
	if len(kl.LegoURL) == 0 {
		kl.LegoURL = "https://acme-staging.api.letsencrypt.org/directory"
	}

	kl.LegoSecretName = os.Getenv("LEGO_SECRET_NAME")
	if len(kl.LegoSecretName) == 0 {
		kl.LegoSecretName = "kube-lego-account"
	}

	kl.LegoServiceName = os.Getenv("LEGO_SERVICE_NAME")
	if len(kl.LegoServiceName) == 0 {
		kl.LegoServiceName = "kube-lego"
	}

	kl.LegoIngressName = os.Getenv("LEGO_INGRESS_NAME")
	if len(kl.LegoIngressName) == 0 {
		kl.LegoIngressName = "kube-lego"
	}

	httpPortStr := os.Getenv("LEGO_PORT")
	if len(httpPortStr) == 0 {
		kl.LegoHTTPPort = intstr.FromInt(8080)
	} else {
		i, err := strconv.Atoi(httpPortStr)
		if err != nil {
			return err
		}
		if i <= 0 || i >= 65535 {
			return fmt.Errorf("Wrong port: %d", i)
		}
		kl.LegoHTTPPort = intstr.FromInt(i)

	}

	return nil
}


