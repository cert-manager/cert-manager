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
	"testing"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha2"
	istioapinetworking "istio.io/api/networking/v1beta1"
	"istio.io/client-go/pkg/apis/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func TestEnsureIstio(t *testing.T) {
	tests := map[string]solverFixture{
		"missing Gateway": {
			Challenge: &cmacme.Challenge{
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
			},
			Err: true,
		},
		"should create VirtualService": {
			Challenge: &cmacme.Challenge{
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
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				_, err := s.FakeIstioClient().NetworkingV1beta1().Gateways(defaultTestNamespace).
					Create(context.Background(), &v1beta1.Gateway{
						ObjectMeta: metav1.ObjectMeta{Namespace: defaultTestNamespace, Name: "test-gateway"},
						Spec: istioapinetworking.Gateway{
							Servers: []*istioapinetworking.Server{
								{
									Port:  &istioapinetworking.Port{Number: 1234, Protocol: "TCP", Name: "foo"},
									Hosts: []string{"*"},
								},
							},
							Selector: map[string]string{"foo": "bar"},
						},
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
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.ensureIstio(context.TODO(), test.Challenge, "fakeservice")
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
