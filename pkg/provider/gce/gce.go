package gce

import (
	"errors"
	"fmt"

	"github.com/jetstack/kube-lego/pkg/kubelego_const"
	"github.com/jetstack/kube-lego/pkg/service"

	"github.com/Sirupsen/logrus"
	k8sExtensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
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
	service         kubelego.Service
	usedByNamespace map[string]bool
}

func New(kl kubelego.KubeLego) *Gce {
	return &Gce{
		kubelego:        kl,
		usedByNamespace: map[string]bool{},
	}
}

func (p *Gce) Log() (log *logrus.Entry) {
	return p.kubelego.Log().WithField("context", "provider").WithField("provider", "gce")
}

func (p *Gce) Reset() (err error) {
	p.Log().Debug("reset")
	p.usedByNamespace = map[string]bool{}
	p.service = nil
	return nil
}

func (p *Gce) Finalize() (err error) {
	p.Log().Debug("finalize")

	err = p.updateServices()
	if err != nil {
		return err
	}

	err = p.removeServices()
	return
}

func (p *Gce) removeServices() (err error) {
	// TODO implement me
	return nil
}

func (p *Gce) updateServices() (err error) {
	for namespace, enabled := range p.usedByNamespace {
		if enabled {
			err = p.updateService(namespace)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *Gce) updateService(namespace string) (err error) {
	var svc kubelego.Service = service.New(p.kubelego, namespace, p.kubelego.LegoServiceNameGce())

	svc.SetKubeLegoSpec()
	svc.Object().Spec.Type = "NodePort"
	svc.Object().Spec.Selector = map[string]string{}

	podIP := p.kubelego.LegoPodIP().String()
	p.Log().WithField("pod_ip", podIP).WithField("namespace", namespace).Debug("setting up svc endpoint")
	err = svc.SetEndpoints([]string{podIP})
	if err != nil {
		return err
	}

	return svc.Save()
}

func (p *Gce) Process(ingObj kubelego.Ingress) (err error) {
	ingApi := ingObj.Object()
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

	return ingObj.Save()
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
