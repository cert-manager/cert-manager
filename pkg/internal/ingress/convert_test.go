/*
Copyright 2021 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ingress

import (
	"testing"

	"github.com/stretchr/testify/assert"
	networkingv1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/pointer"
)

var v1TestIngress = &networkingv1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "test-networkingv1-ingress",
		Namespace: "test-networkingv1-namespace",
		Annotations: map[string]string{
			"test.key": "test.value",
		},
		Labels: map[string]string{
			"labelkey": "labelvalue",
		},
	},
	Spec: networkingv1.IngressSpec{
		IngressClassName: pointer.String("bogus-ingress-class"),
		DefaultBackend: &networkingv1.IngressBackend{
			Service: &networkingv1.IngressServiceBackend{
				Name: "default-backend-svc",
				Port: networkingv1.ServiceBackendPort{
					Number: 1234,
				},
			},
		},
		TLS: []networkingv1.IngressTLS{
			{
				Hosts:      []string{"aaa.", "bbb.", "ccc.ddd"},
				SecretName: "test-secret-1",
			},
			{
				Hosts:      []string{"eee"},
				SecretName: "test-secret-2",
			},
		},
		Rules: []networkingv1.IngressRule{
			{
				Host: "aaa",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path:     "/.well-known/acme-challenge",
								PathType: func() *networkingv1.PathType { p := networkingv1.PathTypeImplementationSpecific; return &p }(),
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "test-solver-backend",
										Port: networkingv1.ServiceBackendPort{Number: 80},
									},
								},
							},
						},
					},
				},
			},
		},
	},
}

var v1beta1TestIngress = &networkingv1beta1.Ingress{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "test-networkingv1-ingress",
		Namespace: "test-networkingv1-namespace",
		Annotations: map[string]string{
			"test.key":                    "test.value",
			"kubernetes.io/ingress.class": "bogus-ingress-class",
		},
		Labels: map[string]string{
			"labelkey": "labelvalue",
		},
	},
	Spec: networkingv1beta1.IngressSpec{
		Backend: &networkingv1beta1.IngressBackend{
			ServiceName: "default-backend-svc",
			ServicePort: intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: 1234,
			},
		},
		Rules: []networkingv1beta1.IngressRule{
			{
				Host: "aaa",
				IngressRuleValue: networkingv1beta1.IngressRuleValue{
					HTTP: &networkingv1beta1.HTTPIngressRuleValue{
						Paths: []networkingv1beta1.HTTPIngressPath{
							{
								Path:     "/.well-known/acme-challenge",
								PathType: func() *networkingv1beta1.PathType { p := networkingv1beta1.PathTypeImplementationSpecific; return &p }(),
								Backend: networkingv1beta1.IngressBackend{
									ServiceName: "test-solver-backend",
									ServicePort: intstr.IntOrString{
										Type:   intstr.Int,
										IntVal: 80,
									},
								},
							},
						},
					},
				},
			},
		},
		TLS: []networkingv1beta1.IngressTLS{
			{
				Hosts:      []string{"aaa.", "bbb.", "ccc.ddd"},
				SecretName: "test-secret-1",
			},
			{
				Hosts:      []string{"eee"},
				SecretName: "test-secret-2",
			},
		},
	},
	Status: networkingv1beta1.IngressStatus{},
}

func TestConvert_networking_Ingress_To_v1beta1_Ingress(t *testing.T) {
	in := v1TestIngress.DeepCopy()
	out := &networkingv1beta1.Ingress{}
	err := Convert_networking_Ingress_To_v1beta1_Ingress(in, out, nil)
	assert.NoError(t, err, "converting networking v1 to networking v1beta1 Ingress should not fail")
	expected := v1beta1TestIngress.DeepCopy()
	assert.Equal(t, expected, out, "Conversion from networking v1 to networking v1beta1 Ingress was not as expected")
}

func TestConvert_v1beta1_Ingress_To_networking_Ingress(t *testing.T) {
	in := v1beta1TestIngress.DeepCopy()
	out := &networkingv1.Ingress{}
	err := Convert_v1beta1_Ingress_To_networking_Ingress(in, out, nil)
	assert.NoError(t, err, "converting networking v1beta1 to networking v1 Ingress should not fail")
	expected := v1TestIngress.DeepCopy()
	assert.Equal(t, expected, out, "Conversion from networking v1beta1 to networking v1 Ingress was not as expected")
}
