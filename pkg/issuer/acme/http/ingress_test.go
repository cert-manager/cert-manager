/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package http

import (
	"fmt"
	"reflect"
	"testing"

	"k8s.io/api/extensions/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apimachinery/pkg/util/intstr"
	coretesting "k8s.io/client-go/testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/test/util/generate"
)

func TestGetIngressesForChallenge(t *testing.T) {
	const createdIngressKey = "createdIngress"
	tests := map[string]solverFixture{
		"should return one ingress that matches": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:      "test",
				Namespace: defaultTestNamespace,
				DNSNames:  []string{"example.com"},
				SolverConfig: v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				ing, err := s.Solver.createIngress(s.Certificate, "fakeservice", s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.testResources[createdIngressKey] = ing
				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				createdIngress := s.testResources[createdIngressKey].(*v1beta1.Ingress)
				resp := args[0].([]*v1beta1.Ingress)
				if len(resp) != 1 {
					t.Errorf("expected one ingress to be returned, but got %d", len(resp))
					t.Fail()
					return
				}
				if !reflect.DeepEqual(resp[0], createdIngress) {
					t.Errorf("Expected %v to equal %v", resp[0], createdIngress)
				}
			},
		},
		"should not return an ingress for the same certificate but different domain": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:      "test",
				Namespace: defaultTestNamespace,
				DNSNames:  []string{"example.com"},
				SolverConfig: v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				_, err := s.Solver.createIngress(s.Certificate, "fakeservice", v1alpha1.ACMEOrderChallenge{
					Domain: "notexample.com",
				})
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				resp := args[0].([]*v1beta1.Ingress)
				if len(resp) != 0 {
					t.Errorf("expected zero ingresses to be returned, but got %d", len(resp))
					t.Fail()
					return
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.getIngressesForChallenge(test.Certificate, test.Challenge)
			if err != nil && !test.Err {
				t.Errorf("Expected function to not error, but got: %v", err)
			}
			if err == nil && test.Err {
				t.Errorf("Expected function to get an error, but got: %v", err)
			}
			test.Finish(t, resp, err)
		})
	}
}

func TestCleanupIngresses(t *testing.T) {
	const createdIngressKey = "createdIngress"
	tests := map[string]solverFixture{
		"should delete ingress resource": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testurl",
				SolverConfig: v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{
						IngressClass: strPtr("nginx"),
					},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
				Token:  "abcd",
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				ing, err := s.Solver.createIngress(s.Certificate, "fakeservice", s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				s.testResources[createdIngressKey] = ing
				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				createdIngress := s.testResources[createdIngressKey].(*v1beta1.Ingress)
				ing, err := s.Builder.FakeKubeClient().ExtensionsV1beta1().Ingresses(s.Certificate.Namespace).Get(createdIngress.Name, metav1.GetOptions{})
				if err != nil && !apierrors.IsNotFound(err) {
					t.Errorf("error when getting test ingress, expected 'not found' but got: %v", err)
				}
				if !apierrors.IsNotFound(err) {
					t.Errorf("expected ingress %q to not exist, but the resource was found: %+v", createdIngress.Name, ing)
				}
			},
		},
		"should not delete ingress resources without appropriate labels": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testurl",
				SolverConfig: v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{
						IngressClass: strPtr("nginx"),
					},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
				Token:  "abcd",
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				ing, err := s.Solver.createIngress(s.Certificate, "fakeservice", v1alpha1.ACMEOrderChallenge{
					Domain: "notexample.com",
					Token:  "abcd",
				})
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				s.testResources[createdIngressKey] = ing
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				createdIngress := s.testResources[createdIngressKey].(*v1beta1.Ingress)
				_, err := s.Builder.FakeKubeClient().ExtensionsV1beta1().Ingresses(s.Certificate.Namespace).Get(createdIngress.Name, metav1.GetOptions{})
				if apierrors.IsNotFound(err) {
					t.Errorf("expected ingress resource %q to not be deleted, but it was deleted", createdIngress.Name)
				}
				if err != nil {
					t.Errorf("error getting ingress resource: %v", err)
				}
			},
		},
		"should clean up an ingress with a single challenge path inserted": {
			Builder: &test.Builder{
				KubeObjects: []runtime.Object{
					&v1beta1.Ingress{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "testingress",
							Namespace: defaultTestNamespace,
						},
						Spec: v1beta1.IngressSpec{
							Backend: &v1beta1.IngressBackend{
								ServiceName: "testsvc",
								ServicePort: intstr.FromInt(8080),
							},
							Rules: []v1beta1.IngressRule{
								{
									Host: "example.com",
									IngressRuleValue: v1beta1.IngressRuleValue{
										HTTP: &v1beta1.HTTPIngressRuleValue{
											Paths: []v1beta1.HTTPIngressPath{
												{
													Path: "/.well-known/acme-challenge/abcd",
													Backend: v1beta1.IngressBackend{
														ServiceName: "solversvc",
														ServicePort: intstr.FromInt(8081),
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testurl",
				SolverConfig: v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{
						Ingress: "testingress",
					},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
				Token:  "abcd",
				SolverConfig: v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{
						Ingress: "testingress",
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				expectedIng := s.KubeObjects[0].(*v1beta1.Ingress).DeepCopy()
				expectedIng.Spec.Rules = nil

				actualIng, err := s.Builder.FakeKubeClient().ExtensionsV1beta1().Ingresses(s.Certificate.Namespace).Get(expectedIng.Name, metav1.GetOptions{})
				if apierrors.IsNotFound(err) {
					t.Errorf("expected ingress resource %q to not be deleted, but it was deleted", expectedIng.Name)
				}
				if err != nil {
					t.Errorf("error getting ingress resource: %v", err)
				}

				if !reflect.DeepEqual(expectedIng, actualIng) {
					t.Errorf("expected did not match actual: %v", diff.ObjectDiff(expectedIng, actualIng))
				}
			},
		},
		"should return an error if a delete fails": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testurl",
				SolverConfig: v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{
						IngressClass: strPtr("nginx"),
					},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
				Token:  "abcd",
			},
			Err: true,
			PreFn: func(t *testing.T, s *solverFixture) {
				s.Builder.FakeKubeClient().PrependReactor("delete", "ingresses", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("simulated error")
				})
				ing, err := s.Solver.createIngress(s.Certificate, "fakeservice", s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				s.testResources[createdIngressKey] = ing
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			err := test.Solver.cleanupIngresses(test.Certificate, test.Challenge)
			if err != nil && !test.Err {
				t.Errorf("Expected function to not error, but got: %v", err)
			}
			if err == nil && test.Err {
				t.Errorf("Expected function to get an error, but got: %v", err)
			}
			test.Finish(t)
		})
	}
}
