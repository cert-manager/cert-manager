package http

import (
	"reflect"
	"testing"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/util/generate"
)

func TestEnsureService(t *testing.T) {
	const createdServiceKey = "createdService"
	tests := map[string]solverFixture{
		"should return an existing service if one already exists": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testURL",
				ACMESolverConfig: v1alpha1.ACMESolverConfig{
					HTTP01: &v1alpha1.ACMECertificateHTTP01Config{},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
			},
			PreFn: func(s *solverFixture) {
				svc, err := s.Solver.createService(s.Certificate, s.Challenge)
				if err != nil {
					s.f.T.Errorf("error preparing test: %v", err)
				}
				s.testResources[createdServiceKey] = svc

				// TODO: replace this with expectedActions to make sure no other actions are performed
				// create a reactor that fails the test if a service is created
				s.f.KubeClient().PrependReactor("create", "services", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					s.f.T.Errorf("ensureService should not create a service if one already exists")
					s.f.T.Fail()
					return false, ret, nil
				})

				s.f.Sync()
			},
			CheckFn: func(s *solverFixture, args ...interface{}) {
				createdService := s.testResources[createdServiceKey].(*v1.Service)
				resp := args[0].(*v1.Service)
				if resp == nil {
					s.f.T.Errorf("unexpected service = nil")
					s.f.T.Fail()
					return
				}
				if !reflect.DeepEqual(resp, createdService) {
					s.f.T.Errorf("Expected %v to equal %v", resp, createdService)
				}
			},
		},
		"should create a new service if one does not exist": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testURL",
				ACMESolverConfig: v1alpha1.ACMESolverConfig{
					HTTP01: &v1alpha1.ACMECertificateHTTP01Config{},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
			},
			PreFn: func(s *solverFixture) {
				expectedService := buildService(s.Certificate, s.Challenge)
				// create a reactor that fails the test if a service is created
				s.f.KubeClient().PrependReactor("create", "services", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					service := action.(coretesting.CreateAction).GetObject().(*v1.Service)
					// clear service name as we don't know it yet in the expectedService
					service.Name = ""
					if !reflect.DeepEqual(service, expectedService) {
						s.f.T.Errorf("Expected %v to equal %v", service, expectedService)
					}
					return false, ret, nil
				})

				s.f.Sync()
			},
			CheckFn: func(s *solverFixture, args ...interface{}) {
				resp := args[0].(*v1.Service)
				err := args[1]
				if resp == nil && err == nil {
					s.f.T.Errorf("unexpected service = nil")
					s.f.T.Fail()
					return
				}
				services, err := s.Solver.serviceLister.List(labels.NewSelector())
				if err != nil {
					s.f.T.Errorf("unexpected error listing services: %v", err)
					s.f.T.Fail()
					return
				}
				if len(services) != 1 {
					s.f.T.Errorf("unexpected %d services in lister: %+v", len(services), services)
					s.f.T.Fail()
					return
				}
				if !reflect.DeepEqual(services[0], resp) {
					s.f.T.Errorf("Expected %v to equal %v", services[0], resp)
				}
			},
		},
		"should clean up if multiple services exist": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testURL",
				ACMESolverConfig: v1alpha1.ACMESolverConfig{
					HTTP01: &v1alpha1.ACMECertificateHTTP01Config{},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
			},
			Err: true,
			PreFn: func(s *solverFixture) {
				_, err := s.Solver.createService(s.Certificate, s.Challenge)
				if err != nil {
					s.f.T.Errorf("error preparing test: %v", err)
				}
				_, err = s.Solver.createService(s.Certificate, s.Challenge)
				if err != nil {
					s.f.T.Errorf("error preparing test: %v", err)
				}

				s.f.Sync()
			},
			CheckFn: func(s *solverFixture, args ...interface{}) {
				services, err := s.Solver.serviceLister.List(labels.NewSelector())
				if err != nil {
					s.f.T.Errorf("error listing services: %v", err)
					s.f.T.Fail()
					return
				}
				if len(services) != 0 {
					s.f.T.Errorf("expected services to have been cleaned up, but there were %d services left", len(services))
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.ensureService(test.Certificate, test.Challenge)
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

func TestGetServicesForCertificate(t *testing.T) {
	const createdServiceKey = "createdService"
	tests := map[string]solverFixture{
		"should return one service that matches": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testURL",
				ACMESolverConfig: v1alpha1.ACMESolverConfig{
					HTTP01: &v1alpha1.ACMECertificateHTTP01Config{},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
			},
			PreFn: func(s *solverFixture) {
				ing, err := s.Solver.createService(s.Certificate, s.Challenge)
				if err != nil {
					s.f.T.Errorf("error preparing test: %v", err)
				}

				s.testResources[createdServiceKey] = ing
				s.f.Sync()
			},
			CheckFn: func(s *solverFixture, args ...interface{}) {
				createdService := s.testResources[createdServiceKey].(*v1.Service)
				resp := args[0].([]*v1.Service)
				if len(resp) != 1 {
					s.f.T.Errorf("expected one service to be returned, but got %d", len(resp))
					s.f.T.Fail()
					return
				}
				if !reflect.DeepEqual(resp[0], createdService) {
					s.f.T.Errorf("Expected %v to equal %v", resp[0], createdService)
				}
			},
		},
		"should not return a service for the same certificate but different domain": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:      "test",
				Namespace: defaultTestNamespace,
				DNSNames:  []string{"example.com"},
				ACMESolverConfig: v1alpha1.ACMESolverConfig{
					HTTP01: &v1alpha1.ACMECertificateHTTP01Config{},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
			},
			PreFn: func(s *solverFixture) {
				_, err := s.Solver.createService(s.Certificate, v1alpha1.ACMEOrderChallenge{
					Domain: "invaliddomain",
				})
				if err != nil {
					s.f.T.Errorf("error preparing test: %v", err)
				}

				s.f.Sync()
			},
			CheckFn: func(s *solverFixture, args ...interface{}) {
				resp := args[0].([]*v1.Service)
				if len(resp) != 0 {
					s.f.T.Errorf("expected zero services to be returned, but got %d", len(resp))
					s.f.T.Fail()
					return
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.getServicesForChallenge(test.Certificate, test.Challenge)
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
