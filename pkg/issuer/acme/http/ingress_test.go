/*
Copyright 2020 The cert-manager Authors.

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
	"context"
	"fmt"
	"reflect"
	"testing"

	"k8s.io/api/networking/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apimachinery/pkg/util/intstr"
	coretesting "k8s.io/client-go/testing"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/test"
)

func TestGetIngressesForChallenge(t *testing.T) {
	const createdIngressKey = "createdIngress"
	tests := map[string]solverFixture{
		"should return one ingress that matches": {
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
						},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				ing, err := s.Solver.createIngress(s.Challenge, "fakeservice")
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
		"should return one ingress for IP that matches": {
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "10.0.0.1",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
						},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				ing, err := s.Solver.createIngress(s.Challenge, "fakeservice")
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
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
						},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				differentChallenge := s.Challenge.DeepCopy()
				differentChallenge.Spec.DNSName = "notexample.com"
				_, err := s.Solver.createIngress(differentChallenge, "fakeservice")
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
			resp, err := test.Solver.getIngressesForChallenge(context.TODO(), test.Challenge)
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
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Token:   "abcd",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
								Class: strPtr("nginx"),
							},
						},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				ing, err := s.Solver.createIngress(s.Challenge, "fakeservice")
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				s.testResources[createdIngressKey] = ing
				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				createdIngress := s.testResources[createdIngressKey].(*v1beta1.Ingress)
				ing, err := s.Builder.FakeKubeClient().NetworkingV1beta1().Ingresses(s.Challenge.Namespace).Get(context.TODO(), createdIngress.Name, metav1.GetOptions{})
				if err != nil && !apierrors.IsNotFound(err) {
					t.Errorf("error when getting test ingress, expected 'not found' but got: %v", err)
				}
				if !apierrors.IsNotFound(err) {
					t.Errorf("expected ingress %q to not exist, but the resource was found: %+v", createdIngress.Name, ing)
				}
			},
		},
		"should not delete ingress resources without appropriate labels": {
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Token:   "abcd",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
								Class: strPtr("nginx"),
							},
						},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				differentChallenge := s.Challenge.DeepCopy()
				differentChallenge.Spec.DNSName = "notexample.com"
				ing, err := s.Solver.createIngress(differentChallenge, "fakeservice")
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				s.testResources[createdIngressKey] = ing
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				createdIngress := s.testResources[createdIngressKey].(*v1beta1.Ingress)
				_, err := s.Builder.FakeKubeClient().NetworkingV1beta1().Ingresses(s.Challenge.Namespace).Get(context.TODO(), createdIngress.Name, metav1.GetOptions{})
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
			Challenge: &cmacme.Challenge{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testchal",
					Namespace: defaultTestNamespace,
				},
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Token:   "abcd",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
								Name: "testingress",
							},
						},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				expectedIng := s.KubeObjects[0].(*v1beta1.Ingress).DeepCopy()
				expectedIng.Spec.Rules = nil

				actualIng, err := s.Builder.FakeKubeClient().NetworkingV1beta1().Ingresses(s.Challenge.Namespace).Get(context.TODO(), expectedIng.Name, metav1.GetOptions{})
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
		"should clean up an ingress with a single challenge path inserted without removing second HTTP rule": {
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
								{
									Host: "a.example.com",
									IngressRuleValue: v1beta1.IngressRuleValue{
										HTTP: &v1beta1.HTTPIngressRuleValue{
											Paths: []v1beta1.HTTPIngressPath{
												{
													Path: "/",
													Backend: v1beta1.IngressBackend{
														ServiceName: "real-backend-svc",
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
			Challenge: &cmacme.Challenge{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testchal",
					Namespace: defaultTestNamespace,
				},
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Token:   "abcd",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
								Name: "testingress",
							},
						},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				expectedIng := s.KubeObjects[0].(*v1beta1.Ingress).DeepCopy()
				expectedIng.Spec.Rules = []v1beta1.IngressRule{expectedIng.Spec.Rules[1]}

				actualIng, err := s.Builder.FakeKubeClient().NetworkingV1beta1().Ingresses(s.Challenge.Namespace).Get(context.TODO(), expectedIng.Name, metav1.GetOptions{})
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
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Token:   "abcd",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
								Class: strPtr("nginx"),
							},
						},
					},
				},
			},
			Err: true,
			PreFn: func(t *testing.T, s *solverFixture) {
				s.Builder.FakeKubeClient().PrependReactor("delete", "ingresses", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("simulated error")
				})
				ing, err := s.Solver.createIngress(s.Challenge, "fakeservice")
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
			err := test.Solver.cleanupIngresses(context.TODO(), test.Challenge)
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

func TestEnsureIngress(t *testing.T) {
	tests := map[string]solverFixture{
		"should clean up if service name changes": {
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
						},
					},
				},
			},
			Err: true,
			PreFn: func(t *testing.T, s *solverFixture) {
				_, err := s.Solver.createIngress(s.Challenge, "anotherfakeservice")
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				ingresses, err := s.Solver.ingressLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("error listing ingresses: %v", err)
					t.Fail()
					return
				}
				if len(ingresses) != 0 {
					t.Errorf("expected ingresses to have been cleaned up, but there were %d ingresses left", len(ingresses))
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.ensureIngress(context.TODO(), test.Challenge, "fakeservice")
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

func TestMergeIngressObjectMetaWithIngressResourceTemplate(t *testing.T) {
	const createdIngressKey = "createdIngressKey"
	tests := map[string]solverFixture{
		"should use labels and annotations from the template": {
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
								Class: strPtr("nginx"),
								IngressTemplate: &cmacme.ACMEChallengeSolverHTTP01IngressTemplate{
									ACMEChallengeSolverHTTP01IngressObjectMeta: cmacme.ACMEChallengeSolverHTTP01IngressObjectMeta{
										Labels: map[string]string{
											"this is a":           "label",
											cmacme.DomainLabelKey: "44655555555",
										},
										Annotations: map[string]string{
											"nginx.ingress.kubernetes.io/whitelist-source-range":  "0.0.0.0/0,::/0",
											"nginx.org/mergeable-ingress-type":                    "minion",
											"traefik.ingress.kubernetes.io/frontend-entry-points": "http",
										},
									},
								},
							},
						},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				expectedIngress, err := buildIngressResource(s.Challenge, "fakeservice")
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				expectedIngress.Labels = map[string]string{
					"this is a":                         "label",
					cmacme.DomainLabelKey:               "44655555555",
					cmacme.TokenLabelKey:                "1",
					cmacme.SolverIdentificationLabelKey: "true",
				}
				expectedIngress.Annotations = map[string]string{
					"kubernetes.io/ingress.class":                         "nginx",
					"nginx.ingress.kubernetes.io/whitelist-source-range":  "0.0.0.0/0,::/0",
					"nginx.org/mergeable-ingress-type":                    "minion",
					"traefik.ingress.kubernetes.io/frontend-entry-points": "http",
				}
				s.testResources[createdIngressKey] = expectedIngress
				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				expectedIngress := s.testResources[createdIngressKey].(*v1beta1.Ingress)

				resp, ok := args[0].(*v1beta1.Ingress)
				if !ok {
					t.Errorf("expected ingress to be returned, but got %v", args[0])
					t.Fail()
					return
				}

				expectedIngress.OwnerReferences = resp.OwnerReferences
				expectedIngress.Name = resp.Name

				if !reflect.DeepEqual(resp, expectedIngress) {
					t.Errorf("unexpected ingress generated from merge\nexp=%+v\ngot=%+v", expectedIngress, resp)
				}
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.createIngress(test.Challenge, "fakeservice")
			test.Finish(t, resp, err)
		})
	}
}
