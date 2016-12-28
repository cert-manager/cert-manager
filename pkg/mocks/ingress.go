package mocks

import (
	. "github.com/jetstack/kube-lego/pkg/kubelego_const"

	"github.com/golang/mock/gomock"
	k8sApi "k8s.io/kubernetes/pkg/api"
	k8sExtensions "k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/util/intstr"
)

func BasicIngressBackend(service string, port int) k8sExtensions.IngressBackend {
	return k8sExtensions.IngressBackend{
		ServiceName: service,
		ServicePort: intstr.FromInt(port),
	}
}

func BasicIngressRule(host string, path string, backend k8sExtensions.IngressBackend) k8sExtensions.IngressRule {
	return k8sExtensions.IngressRule{
		Host: host,
		IngressRuleValue: k8sExtensions.IngressRuleValue{
			HTTP: &k8sExtensions.HTTPIngressRuleValue{
				Paths: []k8sExtensions.HTTPIngressPath{
					k8sExtensions.HTTPIngressPath{
						Path:    path,
						Backend: backend,
					},
				},
			},
		},
	}
}

func BasicIngress(name string, namespace string) *k8sExtensions.Ingress {
	return &k8sExtensions.Ingress{
		ObjectMeta: k8sApi.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: k8sExtensions.IngressSpec{
			Rules: []k8sExtensions.IngressRule{
				BasicIngressRule(
					"domain1",
					"/*",
					BasicIngressBackend("service1", 8001),
				),
			},
		},
	}
}

func BasicIngressDomain12() *k8sExtensions.Ingress {
	ing := BasicIngress("ingress-domain12", "namespace1")
	ing.Spec.Rules = append(ing.Spec.Rules, BasicIngressRule("domain2", "/*", BasicIngressBackend("service2", 80)))
	return ing
}

func BasicIngressDomain12Challenge12() *k8sExtensions.Ingress {
	ing := BasicIngressDomain12()
	ing.Name = "ingress-domain12-challenge12"

	challengeRule := BasicIngressRule("unused", "/.well-known/acme-challenge/*", BasicIngressBackend("kube-lego-gce", 8080))

	ing.Spec.Rules[0].HTTP.Paths = append(challengeRule.HTTP.Paths, ing.Spec.Rules[0].HTTP.Paths...)
	ing.Spec.Rules[1].HTTP.Paths = append(challengeRule.HTTP.Paths, ing.Spec.Rules[1].HTTP.Paths...)

	return ing
}

func DummyIngress(c *gomock.Controller, tls []Tls, ingress *k8sExtensions.Ingress) *MockIngress {
	mockIng := NewMockIngress(c)
	mockIng.EXPECT().Object().AnyTimes().Return(ingress)
	mockIng.EXPECT().Tls().AnyTimes().Return(tls)
	mockIng.EXPECT().Save().AnyTimes().Return(nil)
	mockIng.EXPECT().Delete().AnyTimes().Return(nil)
	return mockIng
}

func DummyIngressNoRules(c *gomock.Controller, tls []Tls) *MockIngress {
	ing := BasicIngress("ingress-no-rules", "namespace1")
	ing.Spec.Rules = []k8sExtensions.IngressRule{}
	return DummyIngress(
		c,
		tls,
		ing,
	)
}

func DummyIngressDomain1(c *gomock.Controller, tls []Tls) *MockIngress {
	ing := BasicIngress("ingress-domain1", "namespace1")
	return DummyIngress(
		c,
		tls,
		ing,
	)
}

func DummyIngressDomain12(c *gomock.Controller, tls []Tls) *MockIngress {
	ing := BasicIngressDomain12()
	return DummyIngress(
		c,
		tls,
		ing,
	)
}

func DummyIngressDomain12Challenge12(c *gomock.Controller, tls []Tls) *MockIngress {
	return DummyIngress(
		c,
		tls,
		BasicIngressDomain12Challenge12(),
	)
}

func DummyIngressNoRulesTLSDomains134(c *gomock.Controller) *MockIngress {
	ing := BasicIngress("ingress-no-rules", "namespace1")
	ing.Spec.Rules = []k8sExtensions.IngressRule{}
	return DummyIngress(
		c,
		DummyTlsDomain134(c),
		ing,
	)
}
