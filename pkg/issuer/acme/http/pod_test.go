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
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

func TestEnsurePod(t *testing.T) {
	const createdPodKey = "createdPod"
	tests := map[string]solverFixture{
		"should return an existing pod if one already exists": {
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Token:   "token",
					Key:     "key",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
						},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				ing, err := s.Solver.createPod(context.TODO(), s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				s.testResources[createdPodKey] = ing

				// TODO: replace this with expectedActions to make sure no other actions are performed
				// create a reactor that fails the test if a pod is created
				s.Builder.FakeKubeClient().PrependReactor("create", "pods", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					t.Errorf("ensurePod should not create a pod if one already exists")
					t.Fail()
					return false, ret, nil
				})

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				createdPod := s.testResources[createdPodKey].(*corev1.Pod)
				resp := args[0].(*corev1.Pod)
				if resp == nil {
					t.Errorf("unexpected pod = nil")
					t.Fail()
					return
				}
				if !reflect.DeepEqual(resp, createdPod) {
					t.Errorf("Expected %v to equal %v", resp, createdPod)
				}
			},
		},
		"should create a new pod if one does not exist": {
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Token:   "token",
					Key:     "key",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
						},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				expectedPod := s.Solver.buildPod(s.Challenge)
				// create a reactor that fails the test if a pod is created
				s.Builder.FakeKubeClient().PrependReactor("create", "pods", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					pod := action.(coretesting.CreateAction).GetObject().(*corev1.Pod)
					// clear pod name as we don't know it yet in the expectedPod
					pod.Name = ""
					if !reflect.DeepEqual(pod, expectedPod) {
						t.Errorf("Expected %v to equal %v", pod, expectedPod)
					}
					return false, ret, nil
				})

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				resp := args[0].(*corev1.Pod)
				err := args[1]
				if resp == nil && err == nil {
					t.Errorf("unexpected pod = nil")
					t.Fail()
					return
				}
				pods, err := s.Solver.podLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("unexpected error listing pods: %v", err)
					t.Fail()
					return
				}
				if len(pods) != 1 {
					t.Errorf("unexpected %d pods in lister: %+v", len(pods), pods)
					t.Fail()
					return
				}
				if !reflect.DeepEqual(pods[0], resp) {
					t.Errorf("Expected %v to equal %v", pods[0], resp)
				}
			},
		},
		"should clean up if multiple pods exist": {
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Token:   "token",
					Key:     "key",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
						},
					},
				},
			},
			Err: true,
			PreFn: func(t *testing.T, s *solverFixture) {
				_, err := s.Solver.createPod(context.TODO(), s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				_, err = s.Solver.createPod(context.TODO(), s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				pods, err := s.Solver.podLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("error listing pods: %v", err)
					t.Fail()
					return
				}
				if len(pods) != 0 {
					t.Errorf("expected pods to have been cleaned up, but there were %d pods left", len(pods))
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.ensurePod(context.TODO(), test.Challenge)
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

func TestGetPodsForCertificate(t *testing.T) {
	const createdPodKey = "createdPod"
	tests := map[string]solverFixture{
		"should return one pod that matches": {
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
				ing, err := s.Solver.createPod(context.TODO(), s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.testResources[createdPodKey] = ing
				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				createdPod := s.testResources[createdPodKey].(*corev1.Pod)
				resp := args[0].([]*corev1.Pod)
				if len(resp) != 1 {
					t.Errorf("expected one pod to be returned, but got %d", len(resp))
					t.Fail()
					return
				}
				if !reflect.DeepEqual(resp[0], createdPod) {
					t.Errorf("Expected %v to equal %v", resp[0], createdPod)
				}
			},
		},
		"should not return a pod for the same certificate but different domain": {
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
				_, err := s.Solver.createPod(context.TODO(), differentChallenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				resp := args[0].([]*corev1.Pod)
				if len(resp) != 0 {
					t.Errorf("expected zero pods to be returned, but got %d", len(resp))
					t.Fail()
					return
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.getPodsForChallenge(context.TODO(), test.Challenge)
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

func TestMergePodObjectMetaWithPodTemplate(t *testing.T) {
	const createdPodKey = "createdPod"
	tests := map[string]solverFixture{
		"should use labels and annotations from template": {
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
								PodTemplate: &cmacme.ACMEChallengeSolverHTTP01IngressPodTemplate{
									ACMEChallengeSolverHTTP01IngressPodObjectMeta: cmacme.ACMEChallengeSolverHTTP01IngressPodObjectMeta{
										Labels: map[string]string{
											"this is a":           "label",
											cmacme.DomainLabelKey: "44655555555",
										},
										Annotations: map[string]string{
											"sidecar.istio.io/inject": "true",
											"foo":                     "bar",
										},
									},
									Spec: cmacme.ACMEChallengeSolverHTTP01IngressPodSpec{
										PriorityClassName: "high",
										NodeSelector: map[string]string{
											"node": "selector",
										},
										Tolerations: []corev1.Toleration{
											{
												Key:      "key",
												Operator: "Exists",
												Effect:   "NoSchedule",
											},
										},
										ServiceAccountName: "cert-manager",
									},
								},
							},
						},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				resultingPod := s.Solver.buildDefaultPod(s.Challenge)
				resultingPod.Labels = map[string]string{
					"this is a":                         "label",
					cmacme.DomainLabelKey:               "44655555555",
					cmacme.TokenLabelKey:                "1",
					cmacme.SolverIdentificationLabelKey: "true",
				}
				resultingPod.Annotations = map[string]string{
					"sidecar.istio.io/inject": "true",
					"foo":                     "bar",
				}
				resultingPod.Spec.NodeSelector = map[string]string{
					"kubernetes.io/os": "linux",
					"node":             "selector",
				}
				resultingPod.Spec.Tolerations = []corev1.Toleration{
					{
						Key:      "key",
						Operator: "Exists",
						Effect:   "NoSchedule",
					},
				}
				resultingPod.Spec.PriorityClassName = "high"
				resultingPod.Spec.ServiceAccountName = "cert-manager"
				s.testResources[createdPodKey] = resultingPod

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				resultingPod := s.testResources[createdPodKey].(*corev1.Pod)

				resp, ok := args[0].(*corev1.Pod)
				if !ok {
					t.Errorf("expected pod to be returned, but got %v", args[0])
					t.Fail()
					return
				}

				// ignore pointer differences here
				resultingPod.OwnerReferences = resp.OwnerReferences

				if resp.String() != resultingPod.String() {
					t.Errorf("unexpected pod generated from merge\nexp=%s\ngot=%s",
						resultingPod, resp)
					t.Fail()
				}
			},
		},
		"should use default if nothing has changed in template": {
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
				resultingPod := s.Solver.buildDefaultPod(s.Challenge)
				s.testResources[createdPodKey] = resultingPod

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				resultingPod := s.testResources[createdPodKey].(*corev1.Pod)

				resp, ok := args[0].(*corev1.Pod)
				if !ok {
					t.Errorf("expected pod to be returned, but got %v", args[0])
					t.Fail()
					return
				}

				// Owner references need to be checked individually
				if len(resultingPod.OwnerReferences) != len(resp.OwnerReferences) {
					t.Errorf("mismatch owner references length, exp=%d got=%d",
						len(resultingPod.OwnerReferences), len(resp.OwnerReferences))
				} else {
					for i := range resp.OwnerReferences {
						if resp.OwnerReferences[i].String() !=
							resultingPod.OwnerReferences[i].String() {
							t.Errorf("unexpected pod owner references generated from merge\nexp=%s\ngot=%s",
								resp.OwnerReferences[i].String(), resultingPod.OwnerReferences[i].String())
						}
					}
				}

				resp.OwnerReferences = resultingPod.OwnerReferences

				if resp.String() != resultingPod.String() {
					t.Errorf("unexpected pod generated from merge\nexp=%s\ngot=%s",
						resultingPod, resp)
					t.Fail()
				}
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp := test.Solver.buildPod(test.Challenge)
			test.Finish(t, resp, nil)
		})
	}
}
