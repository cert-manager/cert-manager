package nginx

import (
	"github.com/jetstack/kube-lego/pkg/ingress"
	"github.com/jetstack/kube-lego/pkg/kubelego_const"
	"github.com/jetstack/kube-lego/pkg/service"

	"github.com/Sirupsen/logrus"
	k8sExtensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"sort"
)

var _ kubelego.IngressProvider = &Nginx{}

type Nginx struct {
	kubelego kubelego.KubeLego
	hosts    map[string]bool
	ingress  kubelego.Ingress
	service  kubelego.Service
}

func New(kl kubelego.KubeLego) *Nginx {
	return &Nginx{
		kubelego: kl,
		hosts:    map[string]bool{},
	}
}

func (p *Nginx) Log() (log *logrus.Entry) {
	return p.kubelego.Log().WithField("context", "provider").WithField("provider", "nginx")
}

func (p *Nginx) Reset() error {
	p.Log().Debug("reset")
	p.hosts = map[string]bool{}
	return nil
}

func (p *Nginx) Finalize() error {
	p.Log().Debug("finalize")

	if p.ingress == nil {
		p.ingress = ingress.New(p.kubelego, p.kubelego.LegoNamespace(), p.kubelego.LegoIngressNameNginx())
	}
	if p.service == nil {
		p.service = service.New(p.kubelego, p.kubelego.LegoNamespace(), p.kubelego.LegoServiceNameNginx())
	}

	if len(p.hosts) < 1 {
		p.Log().Info("disable provider no TLS hosts found")

		err := p.service.Delete()
		if err != nil {
			p.Log().Error(err)
		}

		err = p.ingress.Delete()
		if err != nil {
			p.Log().Error(err)
		}
	} else {
		err := p.updateService()
		if err != nil {
			p.Log().Error(err)
		}
		err = p.updateIngress()
		if err != nil {
			p.Log().Error(err)
		}
	}

	p.service = nil
	p.ingress = nil
	return nil
}

func (p *Nginx) getHosts() (hosts []string) {
	for host, enabled := range p.hosts {
		if enabled {
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	return
}

func (p *Nginx) updateService() error {

	p.service.SetKubeLegoSpec()
	return p.service.Save()

}

func (p *Nginx) updateIngress() error {

	ing := p.ingress.Object()
	rules := []k8sExtensions.IngressRule{}
	paths := []k8sExtensions.HTTPIngressPath{
		k8sExtensions.HTTPIngressPath{
			Path: kubelego.AcmeHttpChallengePath,
			Backend: k8sExtensions.IngressBackend{
				ServiceName: p.kubelego.LegoServiceNameNginx(),
				ServicePort: p.kubelego.LegoHTTPPort(),
			},
		},
	}
	ruleValue := k8sExtensions.IngressRuleValue{
		&k8sExtensions.HTTPIngressRuleValue{
			Paths: paths,
		},
	}
	for _, host := range p.getHosts() {
		rules = append(rules, k8sExtensions.IngressRule{
			Host:             host,
			IngressRuleValue: ruleValue,
		})
	}

	ing.Annotations = map[string]string{
		kubelego.AnnotationIngressChallengeEndpoints: "true",
		kubelego.AnnotationSslRedirect:               "false",
		kubelego.AnnotationIngressClass:              p.kubelego.LegoDefaultIngressClass(),
	}

	ing.Spec = k8sExtensions.IngressSpec{
		Rules: rules,
	}

	return p.ingress.Save()
}

func (p *Nginx) Process(ing kubelego.Ingress) error {
	for _, tls := range ing.Tls() {
		for _, host := range tls.Hosts() {
			p.hosts[host] = true
		}
	}
	return nil
}
