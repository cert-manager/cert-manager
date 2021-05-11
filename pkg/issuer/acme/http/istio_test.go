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

package http

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/http/internal/istio"
)

func TestEnsureIstio(t *testing.T) {
	const svcName = "fakeservice"

	const virtualServiceSpecKey = "virtualservicespec"

	virtualServiceGvr := istio.VirtualServiceGvr()

	testChallenge := cmacme.Challenge{
		Spec: cmacme.ChallengeSpec{
			DNSName: "example.com",
			Solver: cmacme.ACMEChallengeSolver{
				HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
					Istio: &cmacme.ACMEChallengeSolverHTTP01Istio{
						Gateways: []string{fmt.Sprintf("%s/test-gateway", defaultTestNamespace)},
					},
				},
			},
		},
	}

	tests := map[string]solverFixture{
		"should create VirtualService": {
			Challenge: &testChallenge,
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				vss, err := s.Solver.virtualServiceLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("error listing VirtualServices: %v", err)
					return
				}
				if len(vss) != 1 {
					t.Errorf("expected one VirtualService to be created, but %d VirtualServices were found", len(vss))
				}
			},
		},
		"should not modify correct VirtualService": {
			Challenge: &testChallenge,
			PreFn: func(t *testing.T, s *solverFixture) {
				virtualServiceSpec := createVirtualServiceSpec(&testChallenge, svcName)
				s.testResources[virtualServiceSpecKey] = virtualServiceSpec
				virtualService := istio.VirtualService{
					ObjectMeta: metav1.ObjectMeta{
						GenerateName:    "test-gateway-",
						Namespace:       testChallenge.Namespace,
						Labels:          podLabels(&testChallenge),
						OwnerReferences: []metav1.OwnerReference{},
					},
					Spec: *virtualServiceSpec,
				}
				unstr, err := virtualService.ToUnstructured()
				if err != nil {
					t.Errorf("error converting to unstructured: %v", err)
				}
				_, err = s.FakeDynamicClient().Resource(virtualServiceGvr).Namespace(testChallenge.Namespace).Create(context.Background(), unstr, metav1.CreateOptions{})
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				vss, err := s.Solver.virtualServiceLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("error listing VirtualServices: %v", err)
					return
				}
				if len(vss) != 1 {
					t.Errorf("expected one VirtualService to be created, but %d VirtualServices were found", len(vss))
					return
				}
				newVirtualService, err := istio.VirtualServiceFromUnstructured(vss[0])
				if err != nil {
					t.Errorf("could not decode retrieved VirtualService: %v", err)
					return
				}

				oldVirtualServiceSpec := s.testResources[virtualServiceSpecKey]
				newVirtualServiceSpec := &newVirtualService.Spec
				if reflect.TypeOf(oldVirtualServiceSpec) != reflect.TypeOf(newVirtualServiceSpec) {
					t.Errorf("types should be equal (error in test)")
				}
				if !reflect.DeepEqual(oldVirtualServiceSpec, newVirtualServiceSpec) {
					t.Errorf("did not expect correct virtualservice to be modified")
				}
			},
		},
		"should fix existing VirtualService": {
			Challenge: &testChallenge,
			PreFn: func(t *testing.T, s *solverFixture) {
				virtualServiceSpec := createVirtualServiceSpec(&testChallenge, svcName+"-needs-fixing")
				s.testResources[virtualServiceSpecKey] = virtualServiceSpec
				virtualService := istio.VirtualService{
					ObjectMeta: metav1.ObjectMeta{
						GenerateName:    "test-gateway-",
						Namespace:       testChallenge.Namespace,
						Labels:          podLabels(&testChallenge),
						OwnerReferences: []metav1.OwnerReference{},
					},
					Spec: *virtualServiceSpec,
				}
				unstr, err := virtualService.ToUnstructured()
				if err != nil {
					t.Errorf("error converting to unstructured: %v", err)
				}
				_, err = s.FakeDynamicClient().Resource(virtualServiceGvr).Namespace(testChallenge.Namespace).Create(context.Background(), unstr, metav1.CreateOptions{})
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				vss, err := s.Solver.virtualServiceLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("error listing VirtualServices: %v", err)
					return
				}
				if len(vss) != 1 {
					t.Errorf("expected one VirtualService to be created, but %d VirtualServices were found", len(vss))
					return
				}
				newVirtualService, err := istio.VirtualServiceFromUnstructured(vss[0])
				if err != nil {
					t.Errorf("could not decode retrieved VirtualService: %v", err)
					return
				}

				oldVirtualServiceSpec := s.testResources[virtualServiceSpecKey]
				newVirtualServiceSpec := &newVirtualService.Spec
				if reflect.TypeOf(oldVirtualServiceSpec) != reflect.TypeOf(newVirtualServiceSpec) {
					t.Errorf("types should be equal (error in test)")
				}
				if reflect.DeepEqual(oldVirtualServiceSpec, newVirtualServiceSpec) {
					t.Errorf("expected existing VirtualService spec to be fixed")
				}
				if newVirtualServiceSpec.Http[0].Route[0].Destination.Host != svcName {
					t.Errorf("expected virtualservice destination service to be fixed")
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
