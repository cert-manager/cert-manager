package secret

import (
	"github.com/munnerz/cert-manager/pkg/kubelego_const"

	k8sApi "k8s.io/client-go/pkg/api/v1"
)

type Secret struct {
	SecretApi *k8sApi.Secret
	exists    bool
	kubelego  kubelego.KubeLego
}
