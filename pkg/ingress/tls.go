package ingress

import (
	"time"

	"github.com/jetstack/kube-lego/pkg/kubelego_const"
	"github.com/jetstack/kube-lego/pkg/secret"
	"github.com/jetstack/kube-lego/pkg/utils"

	"fmt"
	"github.com/Sirupsen/logrus"
	k8sApi "k8s.io/kubernetes/pkg/api"
	"strings"
)

func (t *Tls) Validate() error {
	if len(t.Hosts()) == 0 {
		return fmt.Errorf("No hosts specified")
	}

	if t.SecretName == "" {
		return fmt.Errorf("No secret name specified")
	}
	return nil
}

func (t Tls) SecretMetadata() (meta *k8sApi.ObjectMeta) {
	return &k8sApi.ObjectMeta{
		Namespace: t.ingress.IngressApi.Namespace,
		Name:      t.SecretName,
	}
}

func (t Tls) IngressMetadata() (meta *k8sApi.ObjectMeta) {
	return &k8sApi.ObjectMeta{
		Namespace: t.ingress.IngressApi.Namespace,
		Name:      t.ingress.IngressApi.Name,
	}
}

func (t *Tls) Secret() *secret.Secret {
	meta := t.SecretMetadata()
	return secret.New(t.ingress.kubelego, meta.Namespace, meta.Name)
}

func (t *Tls) Hosts() []string {
	return utils.StringSliceLowerCase(t.IngressTLS.Hosts)
}

func (t *Tls) Log() *logrus.Entry {
	return t.ingress.Log().WithField("context", "ingress_tls")
}

func (i *Tls) newCertNeeded() bool {
	if len(i.Hosts()) == 0 {
		i.Log().Info("no host associated with ingress")
		return false
	}

	tlsSecret := i.Secret()
	if !tlsSecret.Exists() {
		i.Log().Info("no cert associated with ingress")
		return true
	}

	if !tlsSecret.TlsDomainsInclude(i.Hosts()) {
		i.Log().WithField("domains", i.Hosts()).Info("cert does not cover all domains")
		return true
	}

	expireTime, err := tlsSecret.TlsExpireTime()
	if err != nil {
		i.Log().Warn("error while reading expiry time: ", err)
		return true
	}

	timeLeft := expireTime.Sub(time.Now())
	logger := i.Log().WithField("expire_time", expireTime)
	if timeLeft < 48*time.Hour {
		logger.Infof("cert expires within the next 48 hours")
		return true
	} else {
		logger.Infof("cert expires in %.1f days, no renewal needed", timeLeft.Hours()/24)
	}

	return false
}

func (i *Tls) Process() error {

	if !i.newCertNeeded() {
		i.Log().Infof("no cert request needed")
		return nil
	}

	return i.RequestCert()
}

func (i *Tls) RequestCert() error {

	i.Log().Infof("requesting certificate for %s", strings.Join(i.Hosts(), ","))

	certData, err := i.ingress.kubelego.AcmeClient().ObtainCertificate(
		i.Hosts(),
	)
	if err != nil {
		return err
	}

	s := i.Secret()
	s.SecretApi.Annotations = map[string]string{
		kubelego.AnnotationEnabled: "true",
	}
	s.SecretApi.Type = k8sApi.SecretTypeTLS

	s.SecretApi.Data = certData

	return s.Save()
}
