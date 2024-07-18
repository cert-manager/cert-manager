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

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/diff"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

func TestGetGatewayHTTPRouteForChallenge(t *testing.T) {
	const createdHTTPRouteKey = "createdHTTPRoute"
	tests := map[string]solverFixture{
		"should return one httproute that matches": {
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							GatewayHTTPRoute: &cmacme.ACMEChallengeSolverHTTP01GatewayHTTPRoute{},
						},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				httpRoute, err := s.Solver.createGatewayHTTPRoute(context.TODO(), s.Challenge, "fakeservice")
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.testResources[createdHTTPRouteKey] = httpRoute
				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				createdHTTPRoute := s.testResources[createdHTTPRouteKey].(*gwapi.HTTPRoute)
				gotHttpRoute := args[0].(*gwapi.HTTPRoute)
				if !reflect.DeepEqual(gotHttpRoute, createdHTTPRoute) {
					t.Errorf("Expected %v to equal %v", gotHttpRoute, createdHTTPRoute)
				}
			},
		},
		"should return one httproute for IP that matches": {
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "10.0.0.1",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							GatewayHTTPRoute: &cmacme.ACMEChallengeSolverHTTP01GatewayHTTPRoute{},
						},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				httpRoute, err := s.Solver.createGatewayHTTPRoute(context.TODO(), s.Challenge, "fakeservice")
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.testResources[createdHTTPRouteKey] = httpRoute
				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				createdHTTPRoute := s.testResources[createdHTTPRouteKey].(*gwapi.HTTPRoute)
				gotHttpRoute := args[0].(*gwapi.HTTPRoute)
				if !reflect.DeepEqual(gotHttpRoute, createdHTTPRoute) {
					t.Errorf("Expected %v to equal %v", gotHttpRoute, createdHTTPRoute)
				}
			},
		},
		"should not return an httproute for the same certificate but different domain": {
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							GatewayHTTPRoute: &cmacme.ACMEChallengeSolverHTTP01GatewayHTTPRoute{},
						},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				differentChallenge := s.Challenge.DeepCopy()
				differentChallenge.Spec.DNSName = "notexample.com"
				_, err := s.Solver.createGatewayHTTPRoute(context.TODO(), differentChallenge, "fakeservice")
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				gotHttpRoute := args[0].(*gwapi.HTTPRoute)
				if gotHttpRoute != nil {
					t.Errorf("Expected function to not return an HTTPRoute, but got: %v", gotHttpRoute)
				}
			},
		},
		"should clean-up if there are multiple httproute resources": {
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							GatewayHTTPRoute: &cmacme.ACMEChallengeSolverHTTP01GatewayHTTPRoute{},
						},
					},
				},
			},
			Err: true,
			PreFn: func(t *testing.T, s *solverFixture) {
				_, err := s.Solver.createGatewayHTTPRoute(context.TODO(), s.Challenge, "fakeservice")
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				_, err = s.Solver.createGatewayHTTPRoute(context.TODO(), s.Challenge, "fakeservice")
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				httpRoutes, err := s.Solver.httpRouteLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("error listing HTTPRoutes: %v", err)
					t.Fail()
					return
				}
				if len(httpRoutes) != 1 {
					t.Errorf("Expected 1 HTTPRoute, but got: %v", len(httpRoutes))
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.getGatewayHTTPRoute(context.TODO(), test.Challenge)
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

func TestEnsureGatewayHTTPRoute(t *testing.T) {
	tests := map[string]solverFixture{
		"should not create another httproute if one exists": {
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							GatewayHTTPRoute: &cmacme.ACMEChallengeSolverHTTP01GatewayHTTPRoute{},
						},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				_, err := s.Solver.createGatewayHTTPRoute(context.TODO(), s.Challenge, "fakeservice")
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				httpRoutes, err := s.Solver.httpRouteLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("error listing HTTPRoutes: %v", err)
					t.Fail()
					return
				}

				if len(httpRoutes) != 1 {
					t.Errorf("Expected 1 HTTPRoute, but got: %v", len(httpRoutes))
				}

				gotHTTPRouteSpec := httpRoutes[0].Spec
				expectedHTTPRoute := generateHTTPRouteSpec(s.Challenge, "fakeservice")
				if !reflect.DeepEqual(gotHTTPRouteSpec, expectedHTTPRoute) {
					t.Errorf("Expected HTTPRoute specs to match, but got diff:\n%v",
						diff.ObjectDiff(gotHTTPRouteSpec, expectedHTTPRoute))
				}
			},
		},
		"should update challenge httproute if service changes": {
			Challenge: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName: "example.com",
					Solver: cmacme.ACMEChallengeSolver{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							GatewayHTTPRoute: &cmacme.ACMEChallengeSolverHTTP01GatewayHTTPRoute{},
						},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				_, err := s.Solver.createGatewayHTTPRoute(context.TODO(), s.Challenge, "anotherfakeservice")
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				httpRoutes, err := s.Solver.httpRouteLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("error listing HTTPRoutes: %v", err)
					t.Fail()
					return
				}

				if len(httpRoutes) != 1 {
					t.Errorf("Expected 1 HTTPRoute, but got: %v", len(httpRoutes))
				}

				gotHTTPRouteSpec := httpRoutes[0].Spec
				expectedHTTPRoute := generateHTTPRouteSpec(s.Challenge, "fakeservice")
				if !reflect.DeepEqual(gotHTTPRouteSpec, expectedHTTPRoute) {
					t.Errorf("Expected HTTPRoute specs to match, but got diff:\n%v",
						diff.ObjectDiff(gotHTTPRouteSpec, expectedHTTPRoute))
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.ensureGatewayHTTPRoute(context.TODO(), test.Challenge, "fakeservice")
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
