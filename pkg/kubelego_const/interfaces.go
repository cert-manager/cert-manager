package kubelego

import (
	"net"
	"time"

	"github.com/Sirupsen/logrus"
	k8sApi "k8s.io/kubernetes/pkg/api"
	k8sExtensions "k8s.io/kubernetes/pkg/apis/extensions"
	k8sClient "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/util/intstr"
)

type KubeLego interface {
	KubeClient() *k8sClient.Client
	Log() *logrus.Entry
	AcmeClient() Acme
	LegoHTTPPort() intstr.IntOrString
	LegoEmail() string
	LegoURL() string
	LegoNamespace() string
	LegoIngressNameNginx() string
	LegoServiceNameNginx() string
	LegoServiceNameGce() string
	LegoDefaultIngressClass() string
	LegoCheckInterval() time.Duration
	LegoMinimumValidity() time.Duration
	LegoPodIP() net.IP
	IngressProvider(string) (IngressProvider, error)
	Version() string
	AcmeUser() (map[string][]byte, error)
	SaveAcmeUser(map[string][]byte) error
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

type Service interface {
	Object() *k8sApi.Service
	SetKubeLegoSpec()
	SetEndpoints([]string) error
	Save() error
	Delete() error
}

type Secret interface {
	Object() *k8sApi.Secret
	KubeLego() KubeLego
	Exists() bool
	Save() error
	TlsDomains() ([]string, error)
	TlsDomainsInclude(domains []string) bool
	TlsExpireTime() (time.Time, error)
}

type Ingress interface {
	Object() *k8sExtensions.Ingress
	KubeLego() KubeLego
	Log() *logrus.Entry
	Save() error
	Delete() error
	IngressClass() string
	Tls() []Tls
	Ignore() bool
}

type IngressProvider interface {
	Log() *logrus.Entry
	Process(Ingress) error
	Reset() error
	Finalize() error
}
