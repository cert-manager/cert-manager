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
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	coretesting "k8s.io/client-go/testing"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
)

func TestEnsureService(t *testing.T) {
	type testT struct {
		builder     *testpkg.Builder
		chal        *cmacme.Challenge
		expectedErr bool
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
		service = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "cm-acme-http-solver-",
				Namespace:    testNamespace,
				Labels:       podLabels(chal),
				Annotations: map[string]string{
					"auth.istio.io/8089": "NONE",
				},
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(chal, challengeGvk)},
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeNodePort,
				Ports: []corev1.ServicePort{
					{
						Name:       "http",
						Port:       acmeSolverListenPort,
						TargetPort: intstr.FromInt(acmeSolverListenPort),
					},
				},
				Selector: podLabels(chal),
			},
		}
		serviceMeta = &metav1.PartialObjectMetadata{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Service",
			},
			ObjectMeta: service.ObjectMeta,
		}
	)
	tests := map[string]testT{
		"should return an existing service if one already exists": {
			builder: &testpkg.Builder{
				PartialMetadataObjects: []runtime.Object{serviceMeta},
			},
			chal: chal,
		},
		"should create a new service if one does not exist": {
			builder: &testpkg.Builder{
				ExpectedActions: []testpkg.Action{testpkg.NewAction(coretesting.NewCreateAction(corev1.SchemeGroupVersion.WithResource("services"), testNamespace, service))},
			},
			chal: chal,
		},
		"should clean up if multiple services exist": {
			builder: &testpkg.Builder{
				PartialMetadataObjects: []runtime.Object{serviceMeta, func(s metav1.PartialObjectMetadata) *metav1.PartialObjectMetadata { s.Name = "foobar"; return &s }(*serviceMeta)},
				KubeObjects:            []runtime.Object{service, func(s corev1.Service) *corev1.Service { s.Name = "foobar"; return &s }(*service)},
				ExpectedActions: []testpkg.Action{testpkg.NewAction(coretesting.NewDeleteAction(corev1.SchemeGroupVersion.WithResource("services"), testNamespace, "foobar")),
					testpkg.NewAction(coretesting.NewDeleteAction(corev1.SchemeGroupVersion.WithResource("services"), testNamespace, ""))},
			},
			chal:        chal,
			expectedErr: true,
		},
		"http-01 ingress challenge with a service type specified should end up on the generated solver service": {
			chal: func(chal *cmacme.Challenge) *cmacme.Challenge {
				chal.Spec.Solver.HTTP01.Ingress.ServiceType = corev1.ServiceTypeClusterIP
				return chal
			}(chal.DeepCopy()),
			builder: &testpkg.Builder{
				ExpectedActions: []testpkg.Action{testpkg.NewAction(coretesting.NewCreateAction(corev1.SchemeGroupVersion.WithResource("services"), testNamespace, func(s *corev1.Service) *corev1.Service { s.Spec.Type = corev1.ServiceTypeClusterIP; return s }(service.DeepCopy())))},
			},
		},
		"http-01 gateway httpRoute challenge without a service type should default to NodePort": {
			chal: func(chal *cmacme.Challenge) *cmacme.Challenge {
				chal.Spec.Solver.HTTP01.Ingress = nil
				chal.Spec.Solver.HTTP01.GatewayHTTPRoute = &cmacme.ACMEChallengeSolverHTTP01GatewayHTTPRoute{}
				return chal
			}(chal.DeepCopy()),
			builder: &testpkg.Builder{
				ExpectedActions: []testpkg.Action{testpkg.NewAction(coretesting.NewCreateAction(corev1.SchemeGroupVersion.WithResource("services"), testNamespace, service))},
			},
		},
		"http-01 gateway httpRoute challenge with a service type specified should end up on the generated solver service": {
			chal: func(chal *cmacme.Challenge) *cmacme.Challenge {
				chal.Spec.Solver.HTTP01.Ingress = nil
				chal.Spec.Solver.HTTP01.GatewayHTTPRoute = &cmacme.ACMEChallengeSolverHTTP01GatewayHTTPRoute{
					ServiceType: corev1.ServiceTypeClusterIP,
				}
				return chal
			}(chal.DeepCopy()),
			builder: &testpkg.Builder{
				ExpectedActions: []testpkg.Action{testpkg.NewAction(coretesting.NewCreateAction(corev1.SchemeGroupVersion.WithResource("services"), testNamespace, func(s *corev1.Service) *corev1.Service { s.Spec.Type = corev1.ServiceTypeClusterIP; return s }(service.DeepCopy())))},
			},
		},
	}
	for name, scenario := range tests {
		t.Run(name, func(t *testing.T) {
			scenario.builder.T = t
			scenario.builder.InitWithRESTConfig()
			s := &Solver{
				Context:       scenario.builder.Context,
				serviceLister: scenario.builder.HTTP01ResourceMetadataInformersFactory.ForResource(corev1.SchemeGroupVersion.WithResource("services")).Lister(),
			}
			scenario.builder.Start()
			defer scenario.builder.Stop()
			_, err := s.ensureService(context.Background(), scenario.chal)
			if err != nil != scenario.expectedErr {
				t.Fatalf("unexpected error: wants err: %t, got err %v", scenario.expectedErr, err)

			}
			scenario.builder.CheckAndFinish()
		})

	}
}

func TestGetServicesForChallenge(t *testing.T) {
	type testT struct {
		builder            *testpkg.Builder
		chal               *cmacme.Challenge
		wantedServiceMetas []*metav1.PartialObjectMetadata
		expectedErr        bool
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
		service = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "cm-acme-http-solver-",
				Namespace:    testNamespace,
				Labels:       podLabels(chal),
				Annotations: map[string]string{
					"auth.istio.io/8089": "NONE",
				},
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(chal, challengeGvk)},
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeNodePort,
				Ports: []corev1.ServicePort{
					{
						Name:       "http",
						Port:       acmeSolverListenPort,
						TargetPort: intstr.FromInt(acmeSolverListenPort),
					},
				},
				Selector: podLabels(chal),
			},
		}
		serviceMeta = &metav1.PartialObjectMetadata{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Service",
			},
			ObjectMeta: service.ObjectMeta,
		}
	)
	tests := map[string]testT{
		"should return one service that matches": {
			chal: chal,
			builder: &testpkg.Builder{
				PartialMetadataObjects: []runtime.Object{serviceMeta},
			},
			wantedServiceMetas: []*metav1.PartialObjectMetadata{serviceMeta},
		},
	}
	for name, scenario := range tests {
		t.Run(name, func(t *testing.T) {
			scenario.builder.T = t
			scenario.builder.InitWithRESTConfig()
			s := &Solver{
				Context:       scenario.builder.Context,
				serviceLister: scenario.builder.HTTP01ResourceMetadataInformersFactory.ForResource(corev1.SchemeGroupVersion.WithResource("services")).Lister(),
			}
			scenario.builder.Start()
			defer scenario.builder.Stop()
			gotServiceMetas, err := s.getServicesForChallenge(context.Background(), scenario.chal)
			if err != nil != scenario.expectedErr {
				t.Fatalf("unexpected error: wants err: %t, got err %v", scenario.expectedErr, err)

			}
			assert.ElementsMatch(t, gotServiceMetas, scenario.wantedServiceMetas)
			scenario.builder.CheckAndFinish()
		})

	}
}
