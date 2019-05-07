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

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func TestEnsureService(t *testing.T) {
	const createdServiceKey = "createdService"
	tests := map[string]solverFixture{
		"should return an existing service if one already exists": {
			Challenge: &v1alpha1.Challenge{
				Spec: v1alpha1.ChallengeSpec{
					DNSName: "example.com",
					Config: &v1alpha1.SolverConfig{
						HTTP01: &v1alpha1.HTTP01SolverConfig{},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				svc, err := s.Solver.createService(s.Issuer, s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				s.testResources[createdServiceKey] = svc

				// TODO: replace this with expectedActions to make sure no other actions are performed
				// create a reactor that fails the test if a service is created
				s.FakeKubeClient().PrependReactor("create", "services", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					t.Errorf("ensureService should not create a service if one already exists")
					t.Fail()
					return false, ret, nil
				})

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				createdService := s.testResources[createdServiceKey].(*v1.Service)
				resp := args[0].(*v1.Service)
				if resp == nil {
					t.Errorf("unexpected service = nil")
					t.Fail()
					return
				}
				if !reflect.DeepEqual(resp, createdService) {
					t.Errorf("Expected %v to equal %v", resp, createdService)
				}
			},
		},
		"should create a new service if one does not exist": {
			Challenge: &v1alpha1.Challenge{
				Spec: v1alpha1.ChallengeSpec{
					DNSName: "example.com",
					Config: &v1alpha1.SolverConfig{
						HTTP01: &v1alpha1.HTTP01SolverConfig{},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				expectedService, err := buildService(s.Issuer, s.Challenge)
				if err != nil {
					t.Errorf("expectedService returned an error whilst building test fixture: %v", err)
				}
				// create a reactor that fails the test if a service is created
				s.Builder.FakeKubeClient().PrependReactor("create", "services", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					service := action.(coretesting.CreateAction).GetObject().(*v1.Service)
					// clear service name as we don't know it yet in the expectedService
					service.Name = ""
					if !reflect.DeepEqual(service, expectedService) {
						t.Errorf("Expected %v to equal %v", service, expectedService)
					}
					return false, ret, nil
				})

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				resp := args[0].(*v1.Service)
				err := args[1]
				if resp == nil && err == nil {
					t.Errorf("unexpected service = nil")
					t.Fail()
					return
				}
				services, err := s.Solver.serviceLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("unexpected error listing services: %v", err)
					t.Fail()
					return
				}
				if len(services) != 1 {
					t.Errorf("unexpected %d services in lister: %+v", len(services), services)
					t.Fail()
					return
				}
				if !reflect.DeepEqual(services[0], resp) {
					t.Errorf("Expected %v to equal %v", services[0], resp)
				}
			},
		},
		"should clean up if multiple services exist": {
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
				_, err := s.Solver.createService(s.Issuer, s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				_, err = s.Solver.createService(s.Issuer, s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				services, err := s.Solver.serviceLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("error listing services: %v", err)
					t.Fail()
					return
				}
				if len(services) != 0 {
					t.Errorf("expected services to have been cleaned up, but there were %d services left", len(services))
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.ensureService(context.TODO(), test.Issuer, test.Challenge)
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

func TestGetServicesForChallenge(t *testing.T) {
	const createdServiceKey = "createdService"
	tests := map[string]solverFixture{
		"should return one service that matches": {
			Challenge: &v1alpha1.Challenge{
				Spec: v1alpha1.ChallengeSpec{
					DNSName: "example.com",
					Config: &v1alpha1.SolverConfig{
						HTTP01: &v1alpha1.HTTP01SolverConfig{},
					},
				},
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				ing, err := s.Solver.createService(s.Issuer, s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.testResources[createdServiceKey] = ing
				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				createdService := s.testResources[createdServiceKey].(*v1.Service)
				resp := args[0].([]*v1.Service)
				if len(resp) != 1 {
					t.Errorf("expected one service to be returned, but got %d", len(resp))
					t.Fail()
					return
				}
				if !reflect.DeepEqual(resp[0], createdService) {
					t.Errorf("Expected %v to equal %v", resp[0], createdService)
				}
			},
		},
		"should not return a service for the same certificate but different domain": {
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
				_, err := s.Solver.createService(s.Issuer, differentChallenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				resp := args[0].([]*v1.Service)
				if len(resp) != 0 {
					t.Errorf("expected zero services to be returned, but got %d", len(resp))
					t.Fail()
					return
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.getServicesForChallenge(context.TODO(), test.Challenge)
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
