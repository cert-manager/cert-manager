package kubelego

import (
	"time"

	"github.com/Sirupsen/logrus"
	k8sApi "k8s.io/kubernetes/pkg/api"
	k8sClient "k8s.io/kubernetes/pkg/client/unversioned"
)

type KubeLego interface {
	KubeClient() *k8sClient.Client
	Log() *logrus.Entry
	AcmeClient() Acme
	LegoHTTPPort() string
	LegoEmail() string
	LegoURL() string
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
	Process(minimumValidity time.Duration) error
}

type Ingress interface {
	Tls() []Tls
	Ignore() bool
}
