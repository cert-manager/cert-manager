package ingress

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/simonswine/kube-lego/pkg/secret"
	"github.com/simonswine/kube-lego/pkg/kubelego_const"

	"github.com/Sirupsen/logrus"
	"github.com/xenolf/lego/acme"
	k8sApi "k8s.io/kubernetes/pkg/api"
	k8sExtensions "k8s.io/kubernetes/pkg/apis/extensions"
	k8sErrors "k8s.io/kubernetes/pkg/api/errors"
	k8sClient "k8s.io/kubernetes/pkg/client/unversioned"
)

func New(client kubelego.KubeLego, namespace string, name string) *Ingress {
	ingress := &Ingress{
		exists: true,
		kubelego: client,
	}

	var err error
	ingress.IngressApi, err = client.KubeClient().Ingress(namespace).Get(name)
	if err != nil {
		if k8sErrors.IsNotFound(err){
			ingress.IngressApi = &k8sExtensions.Ingress{
				ObjectMeta: k8sApi.ObjectMeta{
					Namespace: namespace,
					Name: name,
				},
			}
			ingress.exists = false


		} else {
			client.Log().Warn("Error during getting secret: ", err)
		}
	}

	return ingress
}

func All(client kubelego.KubeLego) (ingresses []*Ingress, err error){
	ingSlice, err := client.KubeClient().Extensions().Ingress(k8sApi.NamespaceAll).List(k8sApi.ListOptions{})


	if err != nil {
		return
	}

	for i, _ := range ingSlice.Items {
		ingresses = append(
			ingresses,
			&Ingress{
				IngressApi: &ingSlice.Items[i],
				exists: true,
				kubelego: client,
			},
		)
	}
	return ingresses, nil
}

func (i *Ingress) Log() *logrus.Entry {
	log := i.kubelego.Log().WithField("context", "ingress")

	if i.IngressApi != nil && i.IngressApi.Name != "" {
		log = log.WithField("name", i.IngressApi.Name)
	}
	if i.IngressApi != nil && i.IngressApi.Namespace != "" {
		log = log.WithField("namespace", i.IngressApi.Namespace)
	}
	return log
}

func (o *Ingress) client() k8sClient.IngressInterface{
	return o.kubelego.KubeClient().Extensions().Ingress(o.IngressApi.Namespace)
}

func (o *Ingress) Save() (err error) {
	var obj *k8sExtensions.Ingress
	if o.exists {
		obj, err = o.client().Update(o.IngressApi)
	} else {
		obj, err = o.client().Create(o.IngressApi)
	}
	if err != nil {
		return
	}
	o.IngressApi = obj
	return
}


func (i *Ingress) Ignore() bool {
	key := kubelego.AnnotationEnabled
	if val, ok := i.IngressApi.Annotations[key]; ok {
		if strings.ToLower(val) == "true" {
			return false
		}
	}
	i.Log().Infof("ignoring as it has no '%s' annotation", key)
	return true
}

func (i *Ingress) String() string {
	return fmt.Sprintf(
		"<Ingress '%s/%s'>",
		i.IngressApi.Namespace,
		i.IngressApi.Name,
	)
}

// returns ordered list of domains (no duplicates)
func (i *Ingress) Domains() []string {
	domainsMap := make(map[string]bool)

	for _, rule := range i.IngressApi.Spec.Rules {
		domainsMap[rule.Host] = true
	}

	domainsList := []string{}
	for k := range domainsMap {
		domainsList = append(domainsList, k)
	}

	sort.Strings(domainsList)

	return domainsList
}

func (i *Ingress) RequestCert() error {

	// request full bundle
	bundle := true

	// domains to certify
	domains := i.Domains()

	certificates, errs := i.kubelego.LegoClient().ObtainCertificate(domains, bundle, nil)
	if len(errs) != 0 {
		i.Log().Warn(errs)
	}

	return i.StoreCert(&certificates, domains)
}

func (i *Ingress) SecretName() string {
	return fmt.Sprintf("%s-tls", i.IngressApi.Name)
}

func (i *Ingress) Secret() *secret.Secret {
	return secret.New(i.kubelego, i.IngressApi.Namespace, i.SecretName())
}

func (i *Ingress) StoreCert(certs *acme.CertificateResource, domains []string) error {

	s := i.Secret()
	s.SecretApi.Annotations = map[string]string{
		kubelego.AnnotationEnabled: "true",
	}
	s.SecretApi.Type = k8sApi.SecretTypeTLS

	s.SecretApi.Data = map[string][]byte{
		k8sApi.TLSPrivateKeyKey: certs.PrivateKey,
		k8sApi.TLSCertKey: certs.Certificate,
	}

	err := s.Save()
	if err != nil {
		return err
	}


	// update myself
	i.IngressApi.Spec.TLS = []k8sExtensions.IngressTLS{
		k8sExtensions.IngressTLS{
			Hosts:      domains,
			SecretName: i.SecretName(),
		},
	}

	return s.Save()
}

func (i *Ingress) newCertNeeded() bool {
	domains := i.Domains()

	if len(domains) == 0 {
		i.Log().Info("no host associated with ingress")
		return false
	}

	tlsSecret := i.Secret()
	if ! tlsSecret.Exists(){
		tlsSecret.Log().Infof("this is a test")
		i.Log().Info("no cert associated with ingress")
		return true
	}

	if ! tlsSecret.TlsDomainsInclude(domains){
		i.Log().WithField("domains", domains).Info("cert does not cover all domains")
		return true
	}

	expireTime, err := tlsSecret.TlsExpireTime()
	if err != nil {
		i.Log().Warn("error while reading expiry time: ", err)
		return true
	}

	timeLeft := expireTime.Sub(time.Now())
	logger := i.Log().WithField("expire_time", expireTime)
	if timeLeft < 48 * time.Hour {
		logger.Infof("cert expires within the next 48 hours")
		return true
	} else {
		logger.Infof("cert expires in %.1f days, no renewal needed", timeLeft.Hours()/24)
	}

	return false
}

func (i *Ingress) Process() error {

	if ! i.newCertNeeded() {
		i.Log().Infof("no cert request needed")
		return nil
	}


	return i.RequestCert()
}
