package ingress

import (
	"fmt"
	"strings"

	"github.com/jetstack/kube-lego/pkg/kubelego_const"

	"github.com/Sirupsen/logrus"
	k8sApi "k8s.io/kubernetes/pkg/api"
	k8sErrors "k8s.io/kubernetes/pkg/api/errors"
	k8sExtensions "k8s.io/kubernetes/pkg/apis/extensions"
	k8sClient "k8s.io/kubernetes/pkg/client/unversioned"
)

func IsSupportedIngressClass(in string) (out string, err error) {
	out = strings.ToLower(in)
	for _, ingClass := range kubelego.SupportedIngressClasses {
		if ingClass == out {
			return out, nil
		}
	}
	return "", fmt.Errorf("unsupported ingress class '%s'", in)
}

func IgnoreIngress(ing *k8sExtensions.Ingress) error {

	key := kubelego.AnnotationEnabled

	val, ok := ing.Annotations[key]

	if !ok {
		return fmt.Errorf("has no annotiation '%s'", key)
	}

	if strings.ToLower(val) != "true" {
		return fmt.Errorf("annotiation '%s' is not true", key)
	}

	return nil
}

func New(client kubelego.KubeLego, namespace string, name string) *Ingress {
	ingress := &Ingress{
		exists:   true,
		kubelego: client,
	}

	var err error
	ingress.IngressApi, err = client.KubeClient().Ingress(namespace).Get(name)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			ingress.IngressApi = &k8sExtensions.Ingress{
				ObjectMeta: k8sApi.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
			}
			ingress.exists = false

		} else {
			client.Log().Warn("Error during getting secret: ", err)
		}
	}

	return ingress
}

func All(client kubelego.KubeLego) (ingresses []kubelego.Ingress, err error) {
	ingSlice, err := client.KubeClient().Extensions().Ingress(k8sApi.NamespaceAll).List(k8sApi.ListOptions{})

	if err != nil {
		return
	}

	for i, _ := range ingSlice.Items {
		ingresses = append(
			ingresses,
			&Ingress{
				IngressApi: &ingSlice.Items[i],
				exists:     true,
				kubelego:   client,
			},
		)
	}
	return ingresses, nil
}

var _ kubelego.Ingress = &Ingress{}

type Ingress struct {
	IngressApi *k8sExtensions.Ingress
	exists     bool
	kubelego   kubelego.KubeLego
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

func (o *Ingress) client() k8sClient.IngressInterface {
	return o.kubelego.KubeClient().Extensions().Ingress(o.IngressApi.Namespace)
}

func (o *Ingress) Save() (err error) {
	var obj *k8sExtensions.Ingress

	// check if it contians rules
	if len(o.IngressApi.Spec.Rules) > 0 {
		if o.exists {
			obj, err = o.client().Update(o.IngressApi)
		} else {
			obj, err = o.client().Create(o.IngressApi)
			o.exists = true
		}
	} else {
		if o.exists {
			err = o.client().Delete(o.IngressApi.Namespace, &k8sApi.DeleteOptions{})
			obj = nil
		}
	}
	if err != nil {
		return
	}
	o.IngressApi = obj
	return
}

func (i *Ingress) Delete() error {

	if i.IngressApi == nil || !i.exists {
		return nil
	}

	err := i.client().Delete(i.IngressApi.Namespace, &k8sApi.DeleteOptions{})
	if err != nil {
		return err
	}

	i.IngressApi = nil

	return nil
}

func (i *Ingress) Object() *k8sExtensions.Ingress {
	return i.IngressApi
}

func (i *Ingress) IngressClass() string {
	val, ok := i.IngressApi.Annotations[kubelego.AnnotationIngressClass]
	if !ok {
		return i.kubelego.LegoDefaultIngressClass()
	}
	return strings.ToLower(val)
}

func (i *Ingress) Ignore() bool {
	err := IgnoreIngress(i.IngressApi)
	if err != nil {
		i.Log().Info("ignoring as ", err)
		return true
	}

	_, err = IsSupportedIngressClass(i.IngressClass())
	if err != nil {
		i.Log().Info("ignoring as ", err)
		return true
	}

	return false
}

func (i *Ingress) KubeLego() kubelego.KubeLego {
	return i.kubelego
}

func (i *Ingress) Tls() (out []kubelego.Tls) {
	for count, _ := range i.IngressApi.Spec.TLS {
		out = append(out, &Tls{
			IngressTLS: &i.IngressApi.Spec.TLS[count],
			ingress:    i,
		})
	}
	return
}
