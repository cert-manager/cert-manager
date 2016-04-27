package secret

import (
	"github.com/simonswine/kube-lego/pkg/kubelego_const"

	k8sApi "k8s.io/kubernetes/pkg/api"
)

type Secret struct {
	SecretApi *k8sApi.Secret
	exists    bool
	kubelego  kubelego.KubeLego
}
