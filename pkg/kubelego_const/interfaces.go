package kubelego

import (
	"github.com/Sirupsen/logrus"
	"github.com/xenolf/lego/acme"
	k8sApi "k8s.io/kubernetes/pkg/api"
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

type Tls interface {
	Hosts() []string
	SecretMetadata() *k8sApi.ObjectMeta
	IngressMetadata() *k8sApi.ObjectMeta
	Process() error
}
