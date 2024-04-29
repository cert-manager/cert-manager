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
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
)

func TestEnsurePod(t *testing.T) {
	type testT struct {
		builder     *testpkg.Builder
		chal        *cmacme.Challenge
		expectedErr bool
	}
	cpuRequest, err := resource.ParseQuantity("10m")
	assert.NoError(t, err)
	cpuLimit, err := resource.ParseQuantity("100m")
	assert.NoError(t, err)
	memoryRequest, err := resource.ParseQuantity("64Mi")
	assert.NoError(t, err)
	memoryLimit, err := resource.ParseQuantity("64Mi")
	assert.NoError(t, err)
	var (
		testNamespace = "foo"
		chal          = &cmacme.Challenge{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: testNamespace,
			},
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
		}
		pod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "cm-acme-http-solver-",
				Namespace:    testNamespace,
				Labels:       podLabels(chal),
				Annotations: map[string]string{
					"sidecar.istio.io/inject":                        "false",
					"cluster-autoscaler.kubernetes.io/safe-to-evict": "true",
				},
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(chal, challengeGvk)},
			},
			Spec: corev1.PodSpec{
				AutomountServiceAccountToken: ptr.To(false),
				EnableServiceLinks:           ptr.To(false),
				NodeSelector: map[string]string{
					"kubernetes.io/os": "linux",
				},
				RestartPolicy: corev1.RestartPolicyOnFailure,
				SecurityContext: &corev1.PodSecurityContext{
					RunAsNonRoot: ptr.To(true),
					SeccompProfile: &corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					},
				},
				Containers: []corev1.Container{
					{
						Name:            "acmesolver",
						ImagePullPolicy: corev1.PullIfNotPresent,
						Args: []string{
							fmt.Sprintf("--listen-port=%d", acmeSolverListenPort),
							fmt.Sprintf("--domain=%s", chal.Spec.DNSName),
							fmt.Sprintf("--token=%s", chal.Spec.Token),
							fmt.Sprintf("--key=%s", chal.Spec.Key),
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    cpuRequest,
								corev1.ResourceMemory: memoryRequest,
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    cpuLimit,
								corev1.ResourceMemory: memoryLimit,
							},
						},
						Ports: []corev1.ContainerPort{
							{
								Name:          "http",
								ContainerPort: acmeSolverListenPort,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							ReadOnlyRootFilesystem:   ptr.To(true),
							AllowPrivilegeEscalation: ptr.To(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
						},
					},
				},
			},
		}
		podMeta = &metav1.PartialObjectMetadata{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Pod",
			},
			ObjectMeta: pod.ObjectMeta,
		}
	)
	tests := map[string]testT{
		"should do nothing if pod already exists": {
			builder: &testpkg.Builder{
				PartialMetadataObjects: []runtime.Object{podMeta},
				ExpectedActions:        []testpkg.Action{},
			},
			chal: chal,
		},
		"should create a new pod if one does not exist": {
			builder: &testpkg.Builder{
				PartialMetadataObjects: []runtime.Object{},
				ExpectedActions:        []testpkg.Action{testpkg.NewAction(coretesting.NewCreateAction(corev1.SchemeGroupVersion.WithResource("pods"), testNamespace, pod))},
			},
			chal: chal,
		},
		"should clean up if multiple pods exist": {
			builder: &testpkg.Builder{
				PartialMetadataObjects: []runtime.Object{podMeta, func(p metav1.PartialObjectMetadata) *metav1.PartialObjectMetadata { p.Name = "foobar"; return &p }(*podMeta)},
				KubeObjects:            []runtime.Object{pod, func(p corev1.Pod) *corev1.Pod { p.Name = "foobar"; return &p }(*pod)},
				ExpectedActions: []testpkg.Action{testpkg.NewAction(coretesting.NewDeleteAction(corev1.SchemeGroupVersion.WithResource("pods"), testNamespace, "foobar")),
					testpkg.NewAction(coretesting.NewDeleteAction(corev1.SchemeGroupVersion.WithResource("pods"), testNamespace, ""))},
			},
			chal:        chal,
			expectedErr: true,
		},
	}
	for name, scenario := range tests {
		t.Run(name, func(t *testing.T) {
			scenario.builder.T = t
			scenario.builder.InitWithRESTConfig()
			s := &Solver{
				Context:   scenario.builder.Context,
				podLister: scenario.builder.HTTP01ResourceMetadataInformersFactory.ForResource(corev1.SchemeGroupVersion.WithResource("pods")).Lister(),
			}
			s.Context.ACMEOptions = controller.ACMEOptions{
				HTTP01SolverResourceRequestCPU:    cpuRequest,
				HTTP01SolverResourceRequestMemory: memoryRequest,
				HTTP01SolverResourceLimitsCPU:     cpuLimit,
				HTTP01SolverResourceLimitsMemory:  memoryLimit,
				ACMEHTTP01SolverRunAsNonRoot:      true,
			}
			scenario.builder.Start()
			defer scenario.builder.Stop()
			err := s.ensurePod(context.Background(), scenario.chal)
			if err != nil != scenario.expectedErr {
				t.Fatalf("unexpected error: wants err: %t, got err %v", scenario.expectedErr, err)

			}
			scenario.builder.CheckAndFinish()
		})

	}
}

func TestGetPodsForChallenge(t *testing.T) {
	type testT struct {
		builder        *testpkg.Builder
		chal           *cmacme.Challenge
		wantedPodMetas []*metav1.PartialObjectMetadata
		wantsErr       bool
	}
	var (
		testNamespace = "foo"
		chal          = &cmacme.Challenge{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: testNamespace,
			},
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
		}
		pod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName:    "cm-acme-http-solver-",
				Namespace:       testNamespace,
				Labels:          podLabels(chal),
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(chal, challengeGvk)},
			},
		}
		podMeta = &metav1.PartialObjectMetadata{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Pod",
			},
			ObjectMeta: pod.ObjectMeta,
		}
		podMeta2 = &metav1.PartialObjectMetadata{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Pod",
			},
			ObjectMeta: *pod.ObjectMeta.DeepCopy(),
		}
	)
	podMeta2.Labels[cmacme.DomainLabelKey] = "foo"
	tests := map[string]testT{
		"should return one pod that matches": {
			chal: chal,
			builder: &testpkg.Builder{
				PartialMetadataObjects: []runtime.Object{podMeta},
			},
			wantedPodMetas: []*metav1.PartialObjectMetadata{podMeta},
		},
		"should not return a pod for the same certificate but different domain": {
			chal: chal,
			builder: &testpkg.Builder{
				PartialMetadataObjects: []runtime.Object{&metav1.PartialObjectMetadata{}},
			},
		},
	}
	for name, scenario := range tests {
		t.Run(name, func(t *testing.T) {
			scenario.builder.T = t
			scenario.builder.InitWithRESTConfig()
			s := &Solver{
				Context:   scenario.builder.Context,
				podLister: scenario.builder.HTTP01ResourceMetadataInformersFactory.ForResource(corev1.SchemeGroupVersion.WithResource("pods")).Lister(),
			}
			defer scenario.builder.Stop()
			scenario.builder.Start()
			gotPodMetas, err := s.getPodsForChallenge(s.RootContext, scenario.chal)
			if err != nil != scenario.wantsErr {
				t.Fatalf("unexpected error: wants error: %t, got error: %v", scenario.wantsErr, err)
			}
			assert.ElementsMatch(t, gotPodMetas, scenario.wantedPodMetas)
			scenario.builder.CheckAndFinish()
		})
	}
}

func TestMergePodObjectMetaWithPodTemplate(t *testing.T) {
	const createdPodKey = "createdPod"
	tests := map[string]solverFixture{
		"should use labels, annotations and spec fields from template": {
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
											"sidecar.istio.io/inject":                        "true",
											"cluster-autoscaler.kubernetes.io/safe-to-evict": "false",
											"foo": "bar",
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
										ImagePullSecrets:   []corev1.LocalObjectReference{{Name: "cred"}},
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
					"sidecar.istio.io/inject":                        "true",
					"cluster-autoscaler.kubernetes.io/safe-to-evict": "false",
					"foo": "bar",
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
				resultingPod.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "cred"}}
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
