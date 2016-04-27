package ingress

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

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

	for _,ing := range ingSlice.Items {
		ingresses = append(
			ingresses,
			&Ingress{
				IngressApi: &ing,
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

// returns ordered list of tls domains
// * only first tls specification is used,
// * no duplicates alllowed
func (i *Ingress) TlsDomains() []string {
	for _, tls := range i.IngressApi.Spec.TLS {
		return tls.Hosts
		break
	}
	return []string{}
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

func (i *Ingress) StoreCert(certs *acme.CertificateResource, domains []string) error {

	s := secret.New(i.kubelego, i.SecretName(), i.IngressApi.Namespace)

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

func (i *Ingress) Process() error {
	domains := i.Domains()
	tlsDomains := i.TlsDomains()

	if !reflect.DeepEqual(domains, tlsDomains) {
		i.Log().Infof(
			"%s needs certificate update. current tls domains: %v, required domains: %v",
			i.String(),
			tlsDomains,
			domains,
		)
		err := i.RequestCert()
		i.Log().Warnf("Error during processing certificate request for %s: %s", i.String(), err)

	}

	return nil

}
