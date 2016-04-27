package kubelego

import (
	"github.com/Sirupsen/logrus"
	"github.com/xenolf/lego/acme"
	k8sClient "k8s.io/kubernetes/pkg/client/unversioned"
)

type KubeLego interface {
	KubeClient() *k8sClient.Client
	Log() *logrus.Entry
	LegoClient() *acme.Client
}
