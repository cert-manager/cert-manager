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
	"k8s.io/kubernetes/pkg/util/intstr"
	"reflect"
)

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
	err := IgnoreIngress(i.IngressApi)
	if err != nil {
		i.Log().Info("ignoring as ", err)
		return true

	}
	return false
}

func (i *Ingress) SetChallengeEndpoints(domains []string, serviceName string, httpPort intstr.IntOrString) {
	rules := []k8sExtensions.IngressRule{}
	paths := []k8sExtensions.HTTPIngressPath{
		k8sExtensions.HTTPIngressPath{
			Path: kubelego.AcmeHttpChallengePath,
			Backend: k8sExtensions.IngressBackend{
				ServiceName: serviceName,
				ServicePort: httpPort,
			},
		},
	}
	ruleValue := k8sExtensions.IngressRuleValue{
		&k8sExtensions.HTTPIngressRuleValue{
			Paths: paths,
		},
	}
	for _, hostName := range domains {
		rules = append(rules, k8sExtensions.IngressRule{
			Host:             hostName,
			IngressRuleValue: ruleValue,
		})
	}

	i.IngressApi.Annotations = map[string]string{
		kubelego.AnnotationIngressChallengeEndpoints: "true",
		kubelego.AnnotationSslRedirect:               "false",
	}

	i.IngressApi.Spec = k8sExtensions.IngressSpec{
		Rules: rules,
	}

}

func (i *Ingress) UpdateChallengeEndpoints(domains []string, serviceName string, httpPort intstr.IntOrString) error {

	oldRules := i.IngressApi.Spec.Rules
	oldAnnotations := i.IngressApi.Annotations
	i.SetChallengeEndpoints(domains, serviceName, httpPort)

	if reflect.DeepEqual(oldRules, i.IngressApi.Spec.Rules) || reflect.DeepEqual(oldAnnotations, i.IngressApi.Annotations) {
		i.Log().Infof("challenge endpoints don't need an update")
		return nil
	}

	return i.Save()
}

func (i *Ingress) GetChallengeEndpoints() (tlsHosts []string) {
	for _, rules := range i.IngressApi.Spec.Rules {
		for _, path := range rules.HTTP.Paths {
			if path.Path == kubelego.AcmeHttpChallengePath {
				tlsHosts = append(tlsHosts, rules.Host)
			}
		}
	}
	return
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
