/*
Copyright 2019 The Jetstack cert-manager contributors.

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

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func TestEnsureNetworkPolicy(t *testing.T) {
	const createdNetworkPolicyKey = "createdNetworkPolicy"
	tests := map[string]solverFixture{
		"should return an existing networkpolicy if one already exists": {
			Challenge: &v1alpha1.Challenge{
				Spec: v1alpha1.ChallengeSpec{
					DNSName: "example.com",
					Config: &v1alpha1.SolverConfig{
						HTTP01: &v1alpha1.HTTP01SolverConfig{},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				np, err := s.Solver.createNetworkPolicy(s.Issuer, s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				s.testResources[createdNetworkPolicyKey] = np
				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				createdNetworkPolicy := s.testResources[createdNetworkPolicyKey].(*networkingv1.NetworkPolicy)
				resp := args[0].(*networkingv1.NetworkPolicy)
				if resp == nil {
					t.Errorf("unexpected network policy = nil")
					t.Fail()
					return
				}
				if !reflect.DeepEqual(resp, createdNetworkPolicy) {
					t.Errorf("Expected %v to equal %v", resp, createdNetworkPolicy)
				}
			},
		},
		"should create a new network policy if one does not exist": {
			Challenge: &v1alpha1.Challenge{
				Spec: v1alpha1.ChallengeSpec{
					DNSName: "example.com",
					Config: &v1alpha1.SolverConfig{
						HTTP01: &v1alpha1.HTTP01SolverConfig{},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				expectedNetworkPolicy := buildNetworkPolicy(s.Issuer, s.Challenge)

				// create a reactor that fails the test if a network policy is created
				s.Builder.FakeKubeClient().PrependReactor("create", "networkpolicy", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					networkpolicy := action.(coretesting.CreateAction).GetObject().(*networkingv1.NetworkPolicy)
					// clear network policy name as we don't know it yet in the expectedNetworkPolicy
					networkpolicy.Name = ""
					if !reflect.DeepEqual(networkpolicy, expectedNetworkPolicy) {
						t.Errorf("Expected %v to equal %v", networkpolicy, expectedNetworkPolicy)
					}
					return false, ret, nil
				})

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				resp := args[0].(*networkingv1.NetworkPolicy)
				err := args[1]
				if resp == nil && err == nil {
					t.Errorf("unexpected networkpolicy = nil")
					t.Fail()
					return
				}
				networkpolicies, err := s.Solver.networkPolicyLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("unexpected error listing network policies: %v", err)
					t.Fail()
					return
				}
				if len(networkpolicies) != 1 {
					t.Errorf("unexpected %d network policies in lister: %+v", len(networkpolicies), networkpolicies)
					t.Fail()
					return
				}
				if !reflect.DeepEqual(networkpolicies[0], resp) {
					t.Errorf("Expected %v to equal %v", networkpolicies[0], resp)
				}
			},
		},
		"should clean up if multiple network policies exist": {
			Challenge: &v1alpha1.Challenge{
				Spec: v1alpha1.ChallengeSpec{
					DNSName: "example.com",
					Config: &v1alpha1.SolverConfig{
						HTTP01: &v1alpha1.HTTP01SolverConfig{},
					},
				},
			},
			Err: true,
			PreFn: func(t *testing.T, s *solverFixture) {
				_, err := s.Solver.createNetworkPolicy(s.Issuer, s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				_, err = s.Solver.createNetworkPolicy(s.Issuer, s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				networkpolicies, err := s.Solver.networkPolicyLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("error listing network policies: %v", err)
					t.Fail()
					return
				}
				if len(networkpolicies) != 0 {
					t.Errorf("expected network policies to have been cleaned up, but there were %d policies left", len(networkpolicies))
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.ensureNetworkPolicy(context.TODO(), test.Issuer, test.Challenge)
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

func TestGetNetworkPoliciesForChallenge(t *testing.T) {
	const createdNetworkPolicyKey = "createdNetworkPolicy"
	tests := map[string]solverFixture{
		"should return one network policy that matches": {
			Challenge: &v1alpha1.Challenge{
				Spec: v1alpha1.ChallengeSpec{
					DNSName: "example.com",
					Config: &v1alpha1.SolverConfig{
						HTTP01: &v1alpha1.HTTP01SolverConfig{},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				ing, err := s.Solver.createNetworkPolicy(s.Issuer, s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.testResources[createdNetworkPolicyKey] = ing
				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				createdNetworkPolicy := s.testResources[createdNetworkPolicyKey].(*networkingv1.NetworkPolicy)
				resp := args[0].([]*networkingv1.NetworkPolicy)
				if len(resp) != 1 {
					t.Errorf("expected one network policy to be returned, but got %d", len(resp))
					t.Fail()
					return
				}
				if !reflect.DeepEqual(resp[0], createdNetworkPolicy) {
					t.Errorf("Expected %v to equal %v", resp[0], createdNetworkPolicy)
				}
			},
		},
		"should not return a network policy for the same certificate but different domain": {
			Challenge: &v1alpha1.Challenge{
				Spec: v1alpha1.ChallengeSpec{
					DNSName: "example.com",
					Config: &v1alpha1.SolverConfig{
						HTTP01: &v1alpha1.HTTP01SolverConfig{},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				differentChallenge := s.Challenge.DeepCopy()
				differentChallenge.Spec.DNSName = "invaliddomain"
				_, err := s.Solver.createNetworkPolicy(s.Issuer, differentChallenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				resp := args[0].([]*networkingv1.NetworkPolicy)
				if len(resp) != 0 {
					t.Errorf("expected zero network policies to be returned, but got %d", len(resp))
					t.Fail()
					return
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.getNetworkPoliciesForChallenge(context.TODO(), test.Challenge)
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
