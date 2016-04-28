package kubelego

import (
	"github.com/Sirupsen/logrus"
	"github.com/xenolf/lego/acme"
	k8sClient "k8s.io/kubernetes/pkg/client/unversioned"
)

type KubeLego interface {
	KubeClient() *k8sClient.Client
	Log() *logrus.Entry
	AcmeClient() Acme
	LegoClient() *acme.Client
	LegoHTTPPort() string
	LegoEmail() string
	LegoURL() string
	Version() string
}

type Acme interface {
	ObtainCertificate(domains []string) (map[string][]byte, error)
}