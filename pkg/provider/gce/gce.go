package gce

import (
	"errors"
	"fmt"

	"github.com/jetstack/kube-lego/pkg/kubelego_const"

	k8sExtensions "k8s.io/kubernetes/pkg/apis/extensions"
)

const ClassName = "gce"

var ErrorClassNotMatching = errors.New("Ingress class not matching")

var challengePath = fmt.Sprintf("%s/*", kubelego.AcmeHttpChallengePath)

var _ kubelego.IngressProvider = &Gce{}

func getHostMap(ing kubelego.Ingress) map[string]bool {
	hostMap := map[string]bool{}
	for _, tls := range ing.Tls() {
		for _, host := range tls.Hosts() {
			hostMap[host] = true
		}
	}
	return hostMap
}

type Gce struct {
	kubelego        kubelego.KubeLego
	usedByNamespace map[string]bool
}

func New(kl kubelego.KubeLego) *Gce {
	return &Gce{
		kubelego:        kl,
		usedByNamespace: map[string]bool{},
	}
}

func (p *Gce) Init() error {
	p.usedByNamespace = map[string]bool{}
	return nil
}

func (p *Gce) Process(ings []kubelego.Ingress) (errors []error) {
	for _, ing := range ings {
		var err error
		if ing.IngressClass() == ClassName {
			err = p.ProcessIngress(ing)
		}
		errors = append(errors, err)
	}
	return nil
}

func (p *Gce) getHTTPIngressPath() k8sExtensions.HTTPIngressPath {
	return k8sExtensions.HTTPIngressPath{
		Path: challengePath,
		Backend: k8sExtensions.IngressBackend{
			ServiceName: p.kubelego.LegoServiceNameGce(),
			ServicePort: p.kubelego.LegoHTTPPort(),
		},
	}
}

func (p *Gce) ProcessIngress(ingObj kubelego.Ingress) (err error) {
	ingApi := ingObj.Ingress()
	hostsEnabled := getHostMap(ingObj)
	hostsNotConfigured := getHostMap(ingObj)

	var rulesNew []k8sExtensions.IngressRule
	for _, rule := range ingApi.Spec.Rules {

		pathsNew := []k8sExtensions.HTTPIngressPath{}

		// add challenge endpoints first, if needed
		if _, hostEnabled := hostsEnabled[rule.Host]; hostEnabled {
			delete(hostsNotConfigured, rule.Host)
			pathsNew = []k8sExtensions.HTTPIngressPath{
				p.getHTTPIngressPath(),
			}
		}

		// remove existing challenge paths
		for _, path := range rule.HTTP.Paths {
			if path.Path == challengePath {
				continue
			}
			pathsNew = append(pathsNew, path)
		}

		// add rule if it contains at least one path
		if len(pathsNew) > 0 {
			rule.HTTP.Paths = pathsNew
			rulesNew = append(rulesNew, rule)
		}
	}

	// add missing hosts
	for host, _ := range hostsNotConfigured {
		rulesNew = append(rulesNew, k8sExtensions.IngressRule{
			Host: host,
			IngressRuleValue: k8sExtensions.IngressRuleValue{
				HTTP: &k8sExtensions.HTTPIngressRuleValue{
					Paths: []k8sExtensions.HTTPIngressPath{
						p.getHTTPIngressPath(),
					},
				},
			},
		})
	}

	ingApi.Spec.Rules = rulesNew

	if len(hostsEnabled) > 0 {
		p.usedByNamespace[ingApi.Namespace] = true
	}

	return nil
}
