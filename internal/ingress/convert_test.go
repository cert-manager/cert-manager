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
	"regexp"
	"testing"

	fuzz "github.com/google/gofuzz"
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
			"test.key":                    "test.value",
			"kubernetes.io/ingress.class": "bogus-ingress-class",
		},
		Labels: map[string]string{
			"labelkey": "labelvalue",
		},
	},
	Spec: networkingv1.IngressSpec{
		// As discussed in https://github.com/cert-manager/cert-manager/issues/4537
		// the IngressClassName field is not directly equivalent to the
		// kubernetes.io/ingress.class annotation. According to the Ingress graduation KEP:
		// https://github.com/kubernetes/enhancements/blob/master/keps/sig-network/758-ingress-api-group/README.md
		// the annotation, if present, overrides this field.
		//
		// As the goal of cert-manager is to be as widely compatible as possible, we can only use the
		// annotation to describe an ingress class.
		IngressClassName: nil,
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
	tests := map[string]func(t *testing.T){
		"convert networkingv1 Ingresss to networkingv1beta1 Ingress": func(t *testing.T) {
			in := v1TestIngress.DeepCopy()
			out := new(networkingv1beta1.Ingress)
			err := Convert_networking_Ingress_To_v1beta1_Ingress(in, out, nil)
			assert.NoError(t, err, "conversion should not fail")
			expected := v1beta1TestIngress.DeepCopy()
			assert.Equal(t, expected, out, "conversion was not as expected")
		},
		"mutation side effects": func(t *testing.T) {
			in := v1TestIngress.DeepCopy()
			out := &networkingv1beta1.Ingress{}
			err := Convert_networking_Ingress_To_v1beta1_Ingress(in, out, nil)
			assert.NoError(t, err, "conversion should not fail")
			expected := v1beta1TestIngress.DeepCopy()
			assert.Equal(t, expected, out, "conversion was not as expected")
			// as the convert functions use unsafe.Pointer to make out point to the same
			// underlying data as in, in should end up mutated. This test ensures if
			// a future maintainer touches this code they understand the side effects
			assert.Equal(t, in.Annotations, out.Annotations, "conversion did not have expected side effects: annotations differ")
		},
		"ingress without annotations ends up with annotations": func(t *testing.T) {
			in := &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "namespaces",
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: pointer.String("some-class"),
				},
			}
			out := new(networkingv1beta1.Ingress)
			err := Convert_networking_Ingress_To_v1beta1_Ingress(in, out, nil)
			assert.NoError(t, err, "conversion should not fail")
			expected := &networkingv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "namespaces",
					Annotations: map[string]string{
						"kubernetes.io/ingress.class": "some-class",
					},
				},
			}
			assert.Equal(t, expected, out, "conversion was not as expected")
		},
		"v1 -> v1beta1 -> v1 round trip preserves fields": func(t *testing.T) {
			// Something mentioned in a previous code review is we should make sure we do not
			// remove fields during conversion. There may be a better way of doing this, but this
			// test will fill every field with a fuzzer and perform a conversion round trip.

			base := new(networkingv1.Ingress)
			f := fuzz.New().
				// Filling both the port name and port number is invalid so skip the number for now
				// (the fuzzer will put some negative ports in as well).
				SkipFieldsWithPattern(regexp.MustCompile("Number")).
				// The IngressClassNameLogic is tested below
				SkipFieldsWithPattern(regexp.MustCompile("IngressClassName"))
			f.Fuzz(base)

			in := base.DeepCopy()
			expected := in.DeepCopy()
			intermediate := new(networkingv1beta1.Ingress)
			out := new(networkingv1.Ingress)

			err := Convert_networking_Ingress_To_v1beta1_Ingress(in, intermediate, nil)
			assert.NoError(t, err, "conversion from v1 to v1beta1 should not fail")
			err = Convert_v1beta1_Ingress_To_networking_Ingress(intermediate.DeepCopy(), out, nil)
			assert.NoError(t, err, "conversion from v1beta1 to v1 should not fail")
			assert.Equal(t, expected.Spec, out.Spec, "output Spec was not equal to input Spec after round trip")
		},
	}
	for name, test := range tests {
		t.Run(name, test)
	}
}

func TestConvert_v1beta1_Ingress_To_networking_Ingress(t *testing.T) {
	tests := map[string]func(t *testing.T){
		"convert networkingv1beta1 Ingresss to networkingv1 Ingress": func(t *testing.T) {
			in := v1beta1TestIngress.DeepCopy()
			out := new(networkingv1.Ingress)
			err := Convert_v1beta1_Ingress_To_networking_Ingress(in, out, nil)
			assert.NoError(t, err, "conversion should not fail")
			expected := v1TestIngress.DeepCopy()
			assert.Equal(t, expected, out, "conversion was not as expected")
		},
		"conversion with no ingress class annotation works": func(t *testing.T) {
			in := v1beta1TestIngress.DeepCopy()
			out := new(networkingv1.Ingress)
			delete(in.Annotations, "kubernetes.io/ingress.class")
			err := Convert_v1beta1_Ingress_To_networking_Ingress(in, out, nil)
			assert.NoError(t, err, "conversion should not fail")
			assert.Nil(t, out.Spec.IngressClassName, "ingress class should not be set on output")
		},
		"mutation side effects": func(t *testing.T) {
			// as the convert functions use unsafe.Pointer to make out point to the same
			// underlying data as in, in should end up mutated. This test ensures if
			// a future maintainer touches this code they understand the side effects
			in := v1beta1TestIngress.DeepCopy()
			out := new(networkingv1.Ingress)
			err := Convert_v1beta1_Ingress_To_networking_Ingress(in, out, nil)
			assert.NoError(t, err, "conversion should not fail")
			assert.Equal(t, in.Annotations, out.Annotations, "conversion did not have expected side effects: annotations differ")
		},
	}
	for name, test := range tests {
		t.Run(name, test)
	}
}
