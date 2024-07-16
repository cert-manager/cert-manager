package http

import (
	"context"
	"reflect"
	"testing"

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
