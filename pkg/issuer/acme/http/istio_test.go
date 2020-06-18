/*
Copyright 2020 The Jetstack cert-manager contributors.

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

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha2"
	istioapinetworking "istio.io/api/networking/v1beta1"
	"istio.io/client-go/pkg/apis/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func TestEnsureIstio(t *testing.T) {
	const svcName = "fakeservice"

	const virtualServiceSpecKey = "virtualservicespec"

	testChallenge := cmacme.Challenge{
		Spec: cmacme.ChallengeSpec{
			DNSName: "example.com",
			Solver: cmacme.ACMEChallengeSolver{
				HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
					Istio: &cmacme.ACMEChallengeSolverHTTP01Istio{
						GatewayNamespace: defaultTestNamespace,
						GatewayName:      "test-gateway",
					},
				},
			},
		},
	}

	testGateway := v1beta1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: defaultTestNamespace, Name: "test-gateway"},
	}

	tests := map[string]solverFixture{
		"missing Gateway": {
			Challenge: &testChallenge,
			Err:       true,
		},
		"should create VirtualService": {
			Challenge: &testChallenge,
			PreFn: func(t *testing.T, s *solverFixture) {
				_, err := s.FakeIstioClient().NetworkingV1beta1().Gateways(defaultTestNamespace).
					Create(context.Background(), &testGateway, metav1.CreateOptions{})
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				vss, err := s.Solver.virtualServiceLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("error listing virtualservices: %v", err)
					t.Fail()
					return
				}
				if len(vss) != 1 {
					t.Errorf("expected one virtualservice to be created, but %d virtualservices were found", len(vss))
				}
			},
		},
		"should not modify correct VirtualService": {
			Challenge: &testChallenge,
			PreFn: func(t *testing.T, s *solverFixture) {
				gateway, err := s.FakeIstioClient().NetworkingV1beta1().Gateways(defaultTestNamespace).
					Create(context.Background(), &testGateway, metav1.CreateOptions{})
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				virtualServiceSpec := createVirtualServiceSpec(&testChallenge, svcName, gateway)
				s.testResources[virtualServiceSpecKey] = virtualServiceSpec
				_, err = s.FakeIstioClient().NetworkingV1beta1().VirtualServices(defaultTestNamespace).
					Create(context.Background(), &v1beta1.VirtualService{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: defaultTestNamespace,
							Name:      "test-gateway",
							Labels:    podLabels(&testChallenge),
						},
						Spec: virtualServiceSpec,
					}, metav1.CreateOptions{})
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				vss, err := s.Solver.virtualServiceLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("error listing virtualservices: %v", err)
					t.Fail()
					return
				}
				if len(vss) != 1 {
					t.Errorf("expected one virtualservice to be created, but %d virtualservices were found", len(vss))
					t.Fail()
					return
				}

				oldVirtualServiceSpec := s.testResources[virtualServiceSpecKey].(istioapinetworking.VirtualService)
				newVirtualServiceSpec := vss[0].Spec
				if !reflect.DeepEqual(oldVirtualServiceSpec, newVirtualServiceSpec) {
					t.Errorf("did not expect correct virtualservice to be modified")
				}
			},
		},
		"should fix existing VirtualService": {
			Challenge: &testChallenge,
			PreFn: func(t *testing.T, s *solverFixture) {
				gateway, err := s.FakeIstioClient().NetworkingV1beta1().Gateways(defaultTestNamespace).
					Create(context.Background(), &testGateway, metav1.CreateOptions{})
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				virtualServiceSpec := createVirtualServiceSpec(&testChallenge, svcName+"-needs-fixing", gateway)
				s.testResources[virtualServiceSpecKey] = virtualServiceSpec
				_, err = s.FakeIstioClient().NetworkingV1beta1().VirtualServices(defaultTestNamespace).
					Create(context.Background(), &v1beta1.VirtualService{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: defaultTestNamespace,
							Name:      "test-gateway",
							Labels:    podLabels(&testChallenge),
						},
						Spec: virtualServiceSpec,
					}, metav1.CreateOptions{})
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				vss, err := s.Solver.virtualServiceLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("error listing virtualservices: %v", err)
					t.Fail()
					return
				}
				if len(vss) != 1 {
					t.Errorf("expected one virtualservice to be created, but %d virtualservices were found", len(vss))
					t.Fail()
					return
				}

				oldVirtualServiceSpec := s.testResources[virtualServiceSpecKey].(istioapinetworking.VirtualService)
				newVirtualServiceSpec := vss[0].Spec
				if reflect.DeepEqual(oldVirtualServiceSpec, newVirtualServiceSpec) {
					t.Errorf("expected existing virtualservice spec to be fixed")
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.ensureIstio(context.TODO(), test.Challenge, svcName)
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
