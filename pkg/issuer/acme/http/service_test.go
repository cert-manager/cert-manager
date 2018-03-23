package http

import (
	"reflect"
	"testing"

	"k8s.io/api/core/v1"

	"github.com/jetstack/cert-manager/test/util/generate"
)

func TestGetServicesForCertificate(t *testing.T) {
	const createdServiceKey = "createdService"
	tests := map[string]solverFixture{
		"should return one service that matches": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testURL",
			}),
			Domain: "example.com",
			PreFn: func(s *solverFixture) {
				ing, err := s.Solver.createService(s.Certificate, s.Domain)
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
			}),
			Domain: "example.com",
			PreFn: func(s *solverFixture) {
				_, err := s.Solver.createService(s.Certificate, "invaliddomain")
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
			resp, err := test.Solver.getServicesForCertificate(test.Certificate, test.Domain)
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
